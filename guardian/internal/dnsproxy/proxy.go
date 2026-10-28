// Package dnsproxy is a filtering DNS server. Blocked names get NXDOMAIN;
// everything else is forwarded to an upstream resolver over DNS-over-HTTPS.
package dnsproxy

import (
	"bytes"
	"context"
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

	// OnBlocked, if set, is called for every blocked query.
	OnBlocked func(name, client string)
}

type snapshot struct {
	cfg     *config.Config
	matcher *blocklist.Matcher
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
	m, err := buildMatcher(c)
	if err != nil {
		return err
	}
	p.current.Store(&snapshot{cfg: c, matcher: m})
	return nil
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
	addr := state.cfg.ListenAddr
	mux := dns.NewServeMux()
	mux.Handle(".", p)

	packetConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", addr, err)
	}
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		packetConn.Close()
		return fmt.Errorf("listen TCP %s: %w", addr, err)
	}
	udp := &dns.Server{PacketConn: packetConn, Handler: mux}
	tcp := &dns.Server{Listener: tcpListener, Handler: mux}

	started := make(chan struct{}, 2)
	udp.NotifyStartedFunc = func() { started <- struct{}{} }
	tcp.NotifyStartedFunc = func() { started <- struct{}{} }
	startedEvents := (<-chan struct{})(started)
	errC := make(chan error, 2)
	go func() { errC <- udp.ActivateAndServe() }()
	go func() { errC <- tcp.ActivateAndServe() }()

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
			if startedCount == 2 {
				// Both listeners are serving; wait only for cancellation or
				// an unexpected listener exit from this point onward.
				startedEvents = nil
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
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
	// Close the underlying sockets as well: Shutdown can race with a server
	// goroutine that has not yet entered ActivateAndServe.
	_ = packetConn.Close()
	_ = tcpListener.Close()
	for ; completed < 2; completed++ {
		<-errC
	}
	return runErr
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

	if p.shouldBlock(cfg, state.matcher, q.Name) {
		if p.OnBlocked != nil {
			p.OnBlocked(q.Name, w.RemoteAddr().String())
		}
		p.reply(w, r, new(dns.Msg).SetRcode(r, dns.RcodeNameError))
		return
	}

	resp, err := p.forward(cfg, r)
	if err != nil {
		log.Printf("upstream failure for %s: %v", q.Name, err)
		p.reply(w, r, new(dns.Msg).SetRcode(r, dns.RcodeServerFailure)) // fail closed
		return
	}
	p.reply(w, r, resp)
}

func (p *Proxy) shouldBlock(cfg *config.Config, m *blocklist.Matcher, name string) bool {
	if m.Blocked(name) {
		return true
	}
	return cfg.InBedtime(time.Now()) && !m.Allowed(name)
}

// forward sends the query to each upstream in order over DoH (RFC 8484).
func (p *Proxy) forward(cfg *config.Config, r *dns.Msg) (*dns.Msg, error) {
	wire, err := r.Pack()
	if err != nil {
		return nil, err
	}
	if len(cfg.UpstreamDoH) == 0 {
		return nil, fmt.Errorf("no DoH upstreams configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1800*time.Millisecond)
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
