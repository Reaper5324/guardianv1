package blocklist

import "strings"

// presets maps a service name to the domains that make it work. These are a
// starting point; add to blocked_domains in the config as you find gaps.
// Shared CDNs (e.g. fbcdn.net) are left out on purpose so unrelated sites
// don't break. Test the real app and extend as needed.
var presets = map[string][]string{
	"instagram": {"instagram.com", "cdninstagram.com", "instagr.am", "ig.me"},
	"tiktok": {
		"tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com",
		"byteoversea.com", "ibytedtos.com", "musical.ly",
	},
	"snapchat": {"snapchat.com", "sc-cdn.net", "snapkit.com", "snap-dev.net"},
}

// Preset returns the domains for a named service.
func Preset(name string) ([]string, bool) {
	d, ok := presets[strings.ToLower(strings.TrimSpace(name))]
	return d, ok
}

// DoHProviders are hostnames browsers use for DNS-over-HTTPS. Blocking them
// stops hostname-based DoH from bypassing the filter. The Firefox canary
// domain returning NXDOMAIN tells Firefox to turn DoH off by default.
var DoHProviders = []string{
	"use-application-dns.net",
	"dns.google", "dns64.dns.google",
	"cloudflare-dns.com", "one.one.one.one",
	"mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
	"dns.quad9.net", "doh.opendns.com",
	"dns.nextdns.io", "dns.adguard-dns.com",
}
