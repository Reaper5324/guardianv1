package dnsproxy

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	maxCacheEntries = 1024
	maxCacheTTL     = 5 * time.Minute
)

type cacheEntry struct {
	wire      []byte
	storedAt  time.Time
	expiresAt time.Time
}

type responseCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
}

func newResponseCache() *responseCache {
	return &responseCache{entries: make(map[string]cacheEntry)}
}

func (c *responseCache) get(key string, now time.Time) (*dns.Msg, bool) {
	c.mu.Lock()
	entry, ok := c.entries[key]
	if ok && !now.Before(entry.expiresAt) {
		delete(c.entries, key)
		ok = false
	}
	c.mu.Unlock()
	if !ok {
		return nil, false
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(entry.wire); err != nil {
		c.delete(key)
		return nil, false
	}
	age := uint32(now.Sub(entry.storedAt) / time.Second)
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			ttl := rr.Header().Ttl
			if age >= ttl {
				rr.Header().Ttl = 0
			} else {
				rr.Header().Ttl = ttl - age
			}
		}
	}
	return msg, true
}

func (c *responseCache) put(key string, msg *dns.Msg, now time.Time) {
	if msg == nil || msg.Rcode != dns.RcodeSuccess || msg.Truncated || len(msg.Answer) == 0 {
		return
	}
	ttl := uint32(maxCacheTTL / time.Second)
	for _, rr := range msg.Answer {
		if rr.Header().Ttl == 0 {
			return
		}
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	if ttl == 0 {
		return
	}
	if ttl > uint32(maxCacheTTL/time.Second) {
		ttl = uint32(maxCacheTTL / time.Second)
	}

	cached := msg.Copy()
	maxTTL := uint32(maxCacheTTL / time.Second)
	for _, section := range [][]dns.RR{cached.Answer, cached.Ns, cached.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT && rr.Header().Ttl > maxTTL {
				rr.Header().Ttl = maxTTL
			}
		}
	}
	wire, err := cached.Pack()
	if err != nil {
		return
	}
	entry := cacheEntry{wire: wire, storedAt: now, expiresAt: now.Add(time.Duration(ttl) * time.Second)}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= maxCacheEntries {
		c.evictOldest()
	}
	c.entries[key] = entry
}

func (c *responseCache) clear() {
	c.mu.Lock()
	clear(c.entries)
	c.mu.Unlock()
}

func (c *responseCache) delete(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

func (c *responseCache) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range c.entries {
		if oldestKey == "" || entry.expiresAt.Before(oldest) {
			oldestKey, oldest = key, entry.expiresAt
		}
	}
	delete(c.entries, oldestKey)
}
