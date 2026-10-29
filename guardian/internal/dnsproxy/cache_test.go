package dnsproxy

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func cacheResponse(ttl uint32, rcode int) *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Rcode = rcode
	msg.Question = []dns.Question{{Name: "example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	msg.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   []byte{192, 0, 2, 1},
	}}
	return msg
}

func TestResponseCacheRespectsTTLAndBound(t *testing.T) {
	tests := []struct {
		name        string
		ttl         uint32
		advance     time.Duration
		wantHit     bool
		wantTTL     uint32
		wantEntries int
	}{
		{name: "fresh", ttl: 30, wantHit: true, wantTTL: 30, wantEntries: 1},
		{name: "age decremented", ttl: 30, advance: 7 * time.Second, wantHit: true, wantTTL: 23, wantEntries: 1},
		{name: "expired", ttl: 2, advance: 2 * time.Second, wantHit: false},
		{name: "large ttl capped", ttl: 7200, wantHit: true, wantTTL: uint32(maxCacheTTL / time.Second), wantEntries: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := newResponseCache()
			now := time.Now()
			cache.put("key", cacheResponse(tt.ttl, dns.RcodeSuccess), now)
			got, ok := cache.get("key", now.Add(tt.advance))
			if ok != tt.wantHit {
				t.Fatalf("cache hit = %v, want %v", ok, tt.wantHit)
			}
			if ok && got.Answer[0].Header().Ttl != tt.wantTTL {
				t.Errorf("cached TTL = %d, want %d", got.Answer[0].Header().Ttl, tt.wantTTL)
			}
			if len(cache.entries) != tt.wantEntries {
				t.Errorf("entry count = %d, want %d", len(cache.entries), tt.wantEntries)
			}
		})
	}
}

func TestResponseCacheRejectsUncacheableResponsesAndEvicts(t *testing.T) {
	tests := []struct {
		name string
		msg  *dns.Msg
	}{
		{name: "SERVFAIL", msg: cacheResponse(20, dns.RcodeServerFailure)},
		{name: "zero ttl", msg: cacheResponse(0, dns.RcodeSuccess)},
		{name: "truncated", msg: func() *dns.Msg { m := cacheResponse(20, dns.RcodeSuccess); m.Truncated = true; return m }()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := newResponseCache()
			cache.put("key", tt.msg, time.Now())
			if len(cache.entries) != 0 {
				t.Fatal("uncacheable response was stored")
			}
		})
	}

	cache := newResponseCache()
	now := time.Now()
	for i := 0; i <= maxCacheEntries; i++ {
		cache.put(fmt.Sprintf("key-%d", i), cacheResponse(30, dns.RcodeSuccess), now.Add(time.Duration(i)*time.Nanosecond))
	}
	if len(cache.entries) != maxCacheEntries {
		t.Fatalf("entry count = %d, want %d", len(cache.entries), maxCacheEntries)
	}
}
