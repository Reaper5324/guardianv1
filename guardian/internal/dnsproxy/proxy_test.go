package dnsproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"guardian/internal/config"
)

type responseWriter struct {
	msg  *dns.Msg
	addr net.Addr
}

func (w *responseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *responseWriter) RemoteAddr() net.Addr        { return w.addr }
func (w *responseWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *responseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *responseWriter) Close() error                { return nil }
func (w *responseWriter) TsigStatus() error           { return nil }
func (w *responseWriter) TsigTimersOnly(bool)         {}
func (w *responseWriter) Hijack()                     {}

func makeProxy(t *testing.T, upstream string, client *http.Client, blocked, allowed []string) *Proxy {
	t.Helper()
	b, err := json.Marshal(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	var c config.Config
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	c.ListenAddr = "127.0.0.1:5353"
	c.UpstreamDoH = []string{upstream}
	c.BlockedDomains = blocked
	c.AllowedDomains = allowed
	c.BlockDoHProviders = false
	store := &config.Store{}
	if err := store.Set(&c); err != nil {
		t.Fatal(err)
	}
	p, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	p.client = client
	return p
}

func TestServeDNSWithTLSDoH(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Content-Type"); got != "application/dns-message" {
			t.Errorf("Content-Type = %q", got)
		}
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			t.Errorf("unpack query: %v", err)
			return
		}
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)})
		out, err := response.Pack()
		if err != nil {
			t.Errorf("pack response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	defer server.Close()
	// Use the test server's listener port while keeping the configured host an IP literal.
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	upstream := "https://127.0.0.1:" + port + "/dns-query"
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	client = &http.Client{Transport: transport}
	p := makeProxy(t, upstream, client, []string{"blocked.test"}, []string{"safe.blocked.test"})

	tests := []struct {
		name          string
		qname         string
		opcode        int
		qclass        uint16
		wantRcode     int
		wantAnswers   int
		wantTotalCall int
	}{
		{"blocked suffix", "www.blocked.test.", dns.OpcodeQuery, dns.ClassINET, dns.RcodeNameError, 0, 0},
		{"allowlist wins", "safe.blocked.test.", dns.OpcodeQuery, dns.ClassINET, dns.RcodeSuccess, 1, 1},
		{"ordinary forwarding", "outside.test.", dns.OpcodeQuery, dns.ClassINET, dns.RcodeSuccess, 1, 2},
		{"non-query opcode", "outside.test.", dns.OpcodeStatus, dns.ClassINET, dns.RcodeFormatError, 0, 2},
		{"non-IN class", "outside.test.", dns.OpcodeQuery, dns.ClassCHAOS, dns.RcodeFormatError, 0, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := new(dns.Msg)
			query.SetQuestion(tt.qname, dns.TypeA)
			query.Opcode = tt.opcode
			query.Question[0].Qclass = tt.qclass
			writer := &responseWriter{addr: &net.TCPAddr{}}
			p.ServeDNS(writer, query)
			if writer.msg.Rcode != tt.wantRcode || len(writer.msg.Answer) != tt.wantAnswers || calls != tt.wantTotalCall {
				t.Fatalf("response=%v upstream calls=%d", writer.msg, calls)
			}
		})
	}
}

func TestForwardFailsClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	client = &http.Client{Transport: transport}
	p := makeProxy(t, "https://127.0.0.1:"+port+"/dns-query", client, nil, nil)
	q := new(dns.Msg)
	q.SetQuestion("allowed.test.", dns.TypeA)
	if _, err := p.forward(p.current.Load().cfg, q); err == nil {
		t.Fatal("forward succeeded despite upstream failure")
	}
	w := &responseWriter{addr: &net.TCPAddr{}}
	p.ServeDNS(w, q)
	if w.msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("Rcode = %d, want SERVFAIL", w.msg.Rcode)
	}
}

func TestProbeUpstreamsTreatsNXDOMAINAsHealthy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read request", http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			http.Error(w, "decode request", http.StatusBadRequest)
			return
		}
		response := new(dns.Msg)
		response.SetRcode(query, dns.RcodeNameError)
		body, err := response.Pack()
		if err != nil {
			http.Error(w, "encode response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	client = &http.Client{Transport: transport}
	proxy := makeProxy(t, "https://127.0.0.1:"+port+"/dns-query", client, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := proxy.ProbeUpstreams(ctx); err != nil {
		t.Fatalf("ProbeUpstreams treated a valid NXDOMAIN response as unhealthy: %v", err)
	}
}

func makeProxyForAddr(t *testing.T, addr string) *Proxy {
	t.Helper()
	c := config.Default()
	c.ListenAddr = addr
	c.BlockedDomains = []string{"blocked.test"}
	store := &config.Store{}
	if err := store.Set(&c); err != nil {
		t.Fatal(err)
	}
	p, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunWaitsUntilContextCancelled(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	_, port, err := net.SplitHostPort(probe.Addr().String())
	if err != nil {
		probe.Close()
		t.Fatal(err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	p := makeProxyForAddr(t, net.JoinHostPort("127.0.0.1", port))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listening := make(chan struct{})
	p.OnListening = func() { close(listening) }
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	select {
	case <-listening:
	case runErr := <-done:
		t.Fatalf("proxy failed before listening: %v", runErr)
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not start listening")
	}

	query := new(dns.Msg)
	query.SetQuestion("blocked.test.", dns.TypeA)
	for _, network := range []string{"udp", "tcp"} {
		client := &dns.Client{Net: network, Timeout: time.Second}
		response, _, err := client.Exchange(query, p.current.Load().cfg.ListenAddr)
		if err != nil {
			cancel()
			t.Fatalf("%s DNS query: %v", network, err)
		}
		if response.Rcode != dns.RcodeNameError {
			cancel()
			t.Fatalf("%s response code = %d, want NXDOMAIN", network, response.Rcode)
		}
	}
	select {
	case err := <-done:
		cancel()
		t.Fatalf("Run returned before cancellation: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

func TestRunReturnsWhenTCPPortIsBusy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr := listener.Addr().String()
	p := makeProxyForAddr(t, addr)
	done := make(chan error, 1)
	go func() { done <- p.Run(context.Background()) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run succeeded despite occupied TCP port")
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not fail promptly for occupied TCP port")
	}
}

func TestProxyIntegrationFilteringBedtimeFailureAndCache(t *testing.T) {
	var upstreamCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read request", http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			http.Error(w, "decode request", http.StatusBadRequest)
			return
		}
		upstreamCalls.Add(1)
		if query.Question[0].Name == "servfail.test." {
			http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
			return
		}
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name: query.Question[0].Name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: 60,
			},
			A: net.IPv4(192, 0, 2, 1),
		}}
		body, err := response.Pack()
		if err != nil {
			http.Error(w, "encode response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	_, upstreamPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, listenPort, err := net.SplitHostPort(probe.Addr().String())
	if err != nil {
		probe.Close()
		t.Fatal(err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.ListenAddr = net.JoinHostPort("127.0.0.1", listenPort)
	cfg.UpstreamDoH = []string{"https://127.0.0.1:" + upstreamPort + "/dns-query"}
	cfg.BlockedServices = nil
	cfg.BlockedDomains = []string{"blocked.test"}
	cfg.AllowedDomains = []string{"allowed.blocked.test"}
	cfg.BlockDoHProviders = false
	cfg.Timezone = "UTC"
	store := &config.Store{}
	if err := store.Set(&cfg); err != nil {
		t.Fatal(err)
	}
	proxy, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	proxy.client = &http.Client{Transport: transport, Timeout: 2 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	listening := make(chan struct{})
	proxy.OnListening = func() { close(listening) }
	go func() { done <- proxy.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("proxy did not stop after cancellation")
		}
	}()
	select {
	case <-listening:
	case runErr := <-done:
		t.Fatalf("proxy failed before becoming ready: %v", runErr)
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	exchange := func(name string) *dns.Msg {
		t.Helper()
		query := new(dns.Msg)
		query.SetQuestion(name, dns.TypeA)
		response, _, err := (&dns.Client{Net: "udp", Timeout: 2 * time.Second}).Exchange(query, cfg.ListenAddr)
		if err != nil {
			t.Fatalf("query %s: %v", name, err)
		}
		return response
	}

	if response := exchange("blocked.test."); response.Rcode != dns.RcodeNameError {
		t.Errorf("blocked response code = %s, want NXDOMAIN", dns.RcodeToString[response.Rcode])
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("blocked query reached upstream; calls = %d", got)
	}
	if response := exchange("allowed.blocked.test."); response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("allowlisted response = %v, want successful answer", response)
	}
	now := time.Now().UTC()
	cfg.Bedtime = &config.Window{
		Start: now.Add(-time.Minute).Format("15:04"),
		End:   now.Add(time.Minute).Format("15:04"),
	}
	if err := proxy.ApplyConfig(&cfg, nil); err != nil {
		t.Fatalf("enable bedtime: %v", err)
	}
	if response := exchange("bedtime.test."); response.Rcode != dns.RcodeNameError {
		t.Errorf("bedtime response code = %s, want NXDOMAIN", dns.RcodeToString[response.Rcode])
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("blocked/bedtime query reached upstream; calls = %d, want 1", got)
	}
	cfg.Bedtime = nil
	if err := proxy.ApplyConfig(&cfg, nil); err != nil {
		t.Fatalf("disable bedtime: %v", err)
	}
	if response := exchange("servfail.test."); response.Rcode != dns.RcodeServerFailure {
		t.Errorf("failed upstream response code = %s, want SERVFAIL", dns.RcodeToString[response.Rcode])
	}
	if response := exchange("cache.test."); response.Rcode != dns.RcodeSuccess {
		t.Fatalf("first cache response = %s", dns.RcodeToString[response.Rcode])
	}
	if response := exchange("cache.test."); response.Rcode != dns.RcodeSuccess {
		t.Fatalf("cached response = %s", dns.RcodeToString[response.Rcode])
	}
	if got := upstreamCalls.Load(); got != 3 {
		t.Fatalf("upstream calls after cache hit = %d, want 3", got)
	}

	cfg.BlockedDomains = append(cfg.BlockedDomains, "cache.test")
	if err := proxy.ApplyConfig(&cfg, nil); err != nil {
		t.Fatalf("apply config change: %v", err)
	}
	if response := exchange("cache.test."); response.Rcode != dns.RcodeNameError {
		t.Errorf("cached name after becoming blocked returned %s, want NXDOMAIN", dns.RcodeToString[response.Rcode])
	}
	if got := upstreamCalls.Load(); got != 3 {
		t.Errorf("newly blocked cached name reached upstream; calls = %d, want 3", got)
	}
}
