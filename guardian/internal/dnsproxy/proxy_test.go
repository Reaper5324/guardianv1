package dnsproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
