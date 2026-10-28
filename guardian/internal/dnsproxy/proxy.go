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
	matcher atomic.Pointer[blocklist.Matcher]
	client  *http.Client

	// OnBlocked, if set, is called for every blocked query.
	OnBlocked func(name, client string)
}

func New(store *config.Store) (*Proxy, error) {
	p := &Proxy{
		store:  store,
		client: &http.Client{Timeout: 5 * time.Second},
	}
	if err := p.Reload(); err != nil {
		return nil, err
	}
	return p, nil
}

// Reload rebuilds the matcher from the current config. On error the previous
// matcher stays active.
func (p *Proxy) Reload() error {
	m, err := buildMatcher(p.store.Get())
	if err != nil {
		return err
	}
	p.matcher.Store(m)
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
	addr := p.store.Get().ListenAddr
	mux := dns.NewServeMux()
	mux.Handle(".", p)

	udp := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: mux}

	errc := make(chan error, 2)
	go func() { errc <- udp.ListenAndServe() }()
	go func() { errc <- tcp.ListenAndServe() }()

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
	return err
}

// ServeDNS implements dns.Handler.
func (p *Proxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		p.reply(w, r, new(dns.Msg).SetRcode(r, dns.RcodeFormatError))
		return
	}
	q := r.Question[0]
	cfg := p.store.Get()

	if p.shouldBlock(cfg, q.Name) {
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

func (p *Proxy) shouldBlock(cfg *config.Config, name string) bool {
	m := p.matcher.Load()
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
	var lastErr error
	for _, upstream := range cfg.UpstreamDoH {
		resp, err := p.queryDoH(upstream, wire)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Id = r.Id
		return resp, nil
	}
	return nil, lastErr
}

func (p *Proxy) queryDoH(upstream string, wire []byte) (*dns.Msg, error) {
	req, err := http.NewRequest(http.MethodPost, upstream, bytes.NewReader(wire))
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
		}
		resp.Truncate(size)
	}
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("write response: %v", err)
	}
}
