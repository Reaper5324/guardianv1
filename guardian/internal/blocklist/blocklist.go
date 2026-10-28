// Package blocklist matches DNS names against blocked and allowed domains.
// A rule for "example.com" also matches every subdomain of it.
package blocklist

import "strings"

type Matcher struct {
	blocked map[string]struct{}
	allowed map[string]struct{}
}

func New(blocked, allowed []string) *Matcher {
	return &Matcher{blocked: toSet(blocked), allowed: toSet(allowed)}
}

func toSet(domains []string) map[string]struct{} {
	s := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		if d = normalize(d); d != "" {
			s[d] = struct{}{}
		}
	}
	return s
}

func normalize(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

// Allowed reports whether name matches the allowlist.
func (m *Matcher) Allowed(name string) bool {
	return matchSuffix(m.allowed, normalize(name))
}

// Blocked reports whether name should be blocked. The allowlist wins.
func (m *Matcher) Blocked(name string) bool {
	name = normalize(name)
	if matchSuffix(m.allowed, name) {
		return false
	}
	return matchSuffix(m.blocked, name)
}

// matchSuffix checks name, then each parent domain, against the set.
func matchSuffix(set map[string]struct{}, name string) bool {
	for name != "" {
		if _, ok := set[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
	return false
}
