// Package dnsproxy is a filtering DNS server. Blocked names get NXDOMAIN;
// everything else is forwarded to an upstream resolver over DNS-over-HTTPS.
package dnsproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"guardian/internal/blocklist"
	"guardian/internal/config"
)

type Proxy struct {
	store   *config.Store
	current atomic.Pointer[snapshot]
	client  *http.Client
	cache   *responseCache

	// OnBlocked, if set, is called for every blocked query. It must not block.
	OnBlocked      func(name, client string)
	OnBlockedCount func(category string)
	OnListening    func()
}

type snapshot struct {
	cfg            *config.Config
	matcher        *blocklist.Matcher
	cacheNamespace [sha256.Size]byte
}

func New(store *config.Store) (*Proxy, error) {
	p := &Proxy{
		store:  store,
		client: &http.Client{
			Timeout: 1800 * time.Millisecond,
			Transport: &http.Transport{
				// Guardian must connect directly to the configured IP literal;
				// environment proxy settings must not redirect this traffic.
				Proxy: nil,
			},
		},
		cache: newResponseCache(),
	}
	if err := p.Reload(); err != nil {
		return nil, err
	}
	return p, nil
}

// Reload rebuilds the matcher from the current config. On error the previous
// matcher stays active.
func (p *Proxy) Reload() error {
	c := p.store.Get()
	if c == nil {
		return fmt.Errorf("no active config")
	}
	next, err := makeSnapshot(c)
	if err != nil {
		return err
	}
	p.current.Store(next)
	p.cache.clear()
	return nil
}

func (p *Proxy) CurrentConfig() *config.Config {
	state := p.current.Load()
	if state == nil {
		return nil
	}
	return config.Clone(state.cfg)
}

// ApplyConfig validates all derived filtering state before persistence, then
// publishes config and matcher together for DNS readers.
func (p *Proxy) ApplyConfig(c *config.Config, commit func() error) error {
	if c == nil {
		return fmt.Errorf("config must not be nil")
	}
	next, err := makeSnapshot(config.Clone(c))
	if err != nil {
		return err
	}
	if err := p.store.Update(c, commit); err != nil {
		return err
	}
	p.current.Store(next)
	p.cache.clear()
	return nil
}

func makeSnapshot(c *config.Config) (*snapshot, error) {
	m, err := buildMatcher(c)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encode config snapshot: %w", err)
	}
	return &snapshot{cfg: c, matcher: m, cacheNamespace: sha256.Sum256(encoded)}, nil
}

func buildMatcher(c *config.Config) (*blocklist.Matcher, error) {
	blocked := append([]string{}, c.BlockedDomains...)
	for _, s := range c.BlockedServices {
		d, ok := blocklist.Preset(s)
		if !ok {
			return nil, fmt.Errorf("unknown service %q in blocked_services", s)
		}
		blocked = append(blocked, d...)
	}
	if c.BlockDoHProviders {
		blocked = append(blocked, blocklist.DoHProviders...)
	}
	return blocklist.New(blocked, c.AllowedDomains), nil
}

// Run serves UDP and TCP until ctx is cancelled or a listener fails.
func (p *Proxy) Run(ctx context.Context) error {
	state := p.current.Load()
	if state == nil {
		return fmt.Errorf("no active config")
	}
	_, port, err := net.SplitHostPort(state.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("invalid configured listen address: %w", err)
	}
	mux := dns.NewServeMux()
	mux.Handle(".", p)

	listeners := make([]dnsListener, 0, 4)
	for _, family := range []struct {
		network string
		ip      string
	}{
		{network: "4", ip: "127.0.0.1"},
		{network: "6", ip: "::1"},
	} {
		addr := net.JoinHostPort(family.ip, port)
		packetConn, err := net.ListenPacket("udp"+family.network, addr)
		if err != nil {
			closeListeners(listeners)
			return fmt.Errorf("listen UDP %s: %w", addr, err)
		}
		listeners = append(listeners, dnsListener{
			server: &dns.Server{PacketConn: packetConn, Handler: mux},
			close:  packetConn.Close,
		})

		tcpListener, err := net.Listen("tcp"+family.network, addr)
		if err != nil {
			closeListeners(listeners)
			return fmt.Errorf("listen TCP %s: %w", addr, err)
		}
		listeners = append(listeners, dnsListener{
			server: &dns.Server{Listener: tcpListener, Handler: mux},
			close:  tcpListener.Close,
		})
	}

	started := make(chan struct{}, len(listeners))
	for i := range listeners {
		listeners[i].server.NotifyStartedFunc = func() { started <- struct{}{} }
	}
	startedEvents := (<-chan struct{})(started)
	errC := make(chan error, len(listeners))
	for _, listener := range listeners {
		server := listener.server
		go func() { errC <- server.ActivateAndServe() }()
	}

	completed := 0
	startedCount := 0
	ctxDone := ctx.Done()
	var runErr error
	stopping := false
	for !stopping {
		select {
		case <-ctxDone:
			ctxDone = nil
			stopping = true
		case <-startedEvents:
			startedCount++
			if startedCount == len(listeners) {
				// Every listener is serving; wait only for cancellation or
				// an unexpected listener exit from this point onward.
				startedEvents = nil
				if p.OnListening != nil {
					p.OnListening()
				}
			}
		case serverErr := <-errC:
			completed++
			if runErr == nil {
				runErr = serverErr
				if runErr == nil && ctx.Err() == nil {
					runErr = fmt.Errorf("DNS listener stopped unexpectedly")
				}
			}
			stopping = true
		}
	}
	for _, listener := range listeners {
		_ = listener.server.Shutdown()
		// Shutdown may race with an ActivateAndServe call not yet running.
		_ = listener.close()
	}
	for ; completed < len(listeners); completed++ {
		<-errC
	}
	return runErr
}

type dnsListener struct {
	server *dns.Server
	close  func() error
}

func closeListeners(listeners []dnsListener) {
	for _, listener := range listeners {
		_ = listener.close()
	}
}

// ServeDNS implements dns.Handler.
func (p *Proxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if r.Response || r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 || r.Question[0].Qclass != dns.ClassINET {
		p.reply(w, r, new(dns.Msg).SetRcode(r, dns.RcodeFormatError))
		return
	}
	q := r.Question[0]
	state := p.current.Load()
	if state == nil {
		p.reply(w, r, new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}
	cfg := state.cfg

	category := p.blockCategory(cfg, state.matcher, q.Name, time.Now())
	if category != "" {
		if p.OnBlockedCount != nil {
			p.OnBlockedCount(category)
		}
		if p.OnBlocked != nil {
			p.OnBlocked(q.Name, w.RemoteAddr().String())
		}
		p.reply(w, r, new(dns.Msg).SetRcode(r, dns.RcodeNameError))
		return
	}

	key, keyErr := makeCacheKey(state.cacheNamespace, r)
	if keyErr == nil {
		if cached, ok := p.cache.get(key, time.Now()); ok {
			cached.Id = r.Id
			p.reply(w, r, cached)
			return
		}
	}
	resp, err := p.forward(cfg, r)
	if err != nil {
		p.reply(w, r, new(dns.Msg).SetRcode(r, dns.RcodeServerFailure)) // fail closed
		return
	}
	if keyErr == nil {
		p.cache.put(key, resp, time.Now())
	}
	p.reply(w, r, resp)
}

func makeCacheKey(namespace [sha256.Size]byte, query *dns.Msg) (string, error) {
	canonical := query.Copy()
	canonical.Id = 0
	wire, err := canonical.Pack()
	if err != nil {
		return "", err
	}
	return string(namespace[:]) + string(wire), nil
}

func (p *Proxy) blockCategory(cfg *config.Config, m *blocklist.Matcher, name string, now time.Time) string {
	if m.Blocked(name) {
		for _, service := range cfg.BlockedServices {
			domains, ok := blocklist.Preset(service)
			if ok && blocklist.New(domains, nil).Blocked(name) {
				return service
			}
		}
		if cfg.BlockDoHProviders && blocklist.New(blocklist.DoHProviders, nil).Blocked(name) {
			return "doh-provider"
		}
		return "custom"
	}
	if cfg.InBedtime(now) && !m.Allowed(name) {
		return "bedtime"
	}
	return ""
}

func (p *Proxy) ProbeUpstreams(ctx context.Context) error {
	state := p.current.Load()
	if state == nil {
		return fmt.Errorf("no active config")
	}
	query := new(dns.Msg)
	query.SetQuestion("guardian-health.invalid.", dns.TypeA)
	response, err := p.forwardContext(ctx, state.cfg, query)
	if err != nil {
		return err
	}
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("upstream returned DNS rcode %s", dns.RcodeToString[response.Rcode])
	}
	return nil
}

// forward sends the query to each upstream in order over DoH (RFC 8484).
func (p *Proxy) forward(cfg *config.Config, r *dns.Msg) (*dns.Msg, error) {
	return p.forwardContext(context.Background(), cfg, r)
}

func (p *Proxy) forwardContext(parent context.Context, cfg *config.Config, r *dns.Msg) (*dns.Msg, error) {
	wire, err := r.Pack()
	if err != nil {
		return nil, err
	}
	if len(cfg.UpstreamDoH) == 0 {
		return nil, fmt.Errorf("no DoH upstreams configured")
	}
	ctx, cancel := context.WithTimeout(parent, 1800*time.Millisecond)
	defer cancel()
	type result struct {
		resp *dns.Msg
		err  error
	}
	results := make(chan result, len(cfg.UpstreamDoH))
	for _, upstream := range cfg.UpstreamDoH {
		upstream := upstream
		go func() {
			resp, err := p.queryDoH(ctx, upstream, wire)
			results <- result{resp: resp, err: err}
		}()
	}
	var lastErr error
	for range cfg.UpstreamDoH {
		got := <-results
		if got.err != nil {
			lastErr = got.err
			continue
		}
		got.resp.Id = r.Id
		return got.resp, nil
	}
	return nil, lastErr
}

func (p *Proxy) queryDoH(ctx context.Context, upstream string, wire []byte) (*dns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	hr, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer hr.Body.Close()
	if hr.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", upstream, hr.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(hr.Body, 65535))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}

// reply writes resp, truncating for UDP clients when needed.
func (p *Proxy) reply(w dns.ResponseWriter, r *dns.Msg, resp *dns.Msg) {
	if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
		size := dns.MinMsgSize
		if o := r.IsEdns0(); o != nil {
			size = int(o.UDPSize())
			if size < dns.MinMsgSize {
				size = dns.MinMsgSize
			}
		}
		resp.Truncate(size)
	}
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("write response: %v", err)
	}
}
