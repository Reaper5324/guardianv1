// Package config defines Guardian's configuration, validates it, and holds
// the active copy behind an atomic pointer so it can be hot-swapped.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Window is a daily time range in local time, "HH:MM". Overnight ranges
// (start later than end, e.g. 22:00 to 06:00) are supported.
type Window struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type Config struct {
	Version           uint64   `json:"version,omitempty"`
	ListenAddr        string   `json:"listen_addr"`
	UpstreamDoH       []string `json:"upstream_doh"`
	BlockedServices   []string `json:"blocked_services"`
	BlockedDomains    []string `json:"blocked_domains"`
	AllowedDomains    []string `json:"allowed_domains"`
	BlockDoHProviders bool     `json:"block_doh_providers"`
	Bedtime           *Window  `json:"bedtime,omitempty"`
	Timezone          string   `json:"timezone"`

	loc              *time.Location
	bedStart, bedEnd int // minutes since midnight
}

// Default returns the baseline config that files are layered on top of.
func Default() Config {
	return Config{
		ListenAddr:        "127.0.0.1:53",
		UpstreamDoH:       []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"},
		BlockDoHProviders: true,
		Timezone:          "Africa/Johannesburg",
	}
}

// Parse decodes and validates a config. Missing fields keep their defaults.
func Parse(b []byte) (*Config, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("parse config: expected a JSON object")
	}
	c := Default()
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("parse config: trailing data")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func (c *Config) validate() error {
	host, port, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen_addr: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen_addr: host must be a loopback IP literal")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("listen_addr: port must be between 1 and 65535")
	}
	if len(c.UpstreamDoH) == 0 {
		return errors.New("upstream_doh: need at least one upstream")
	}
	for _, raw := range c.UpstreamDoH {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" {
			return fmt.Errorf("upstream_doh %q: must be an https URL", raw)
		}
		if net.ParseIP(u.Hostname()) == nil {
			return fmt.Errorf("upstream_doh %q: host must be an IP literal (the filter cannot resolve names through itself)", raw)
		}
		if u.User != nil || u.Fragment != "" {
			return fmt.Errorf("upstream_doh %q: user information and fragments are not allowed", raw)
		}
	}
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return fmt.Errorf("timezone %q: %w", c.Timezone, err)
	}
	c.loc = loc
	if c.Bedtime != nil {
		if c.bedStart, err = parseHM(c.Bedtime.Start); err != nil {
			return fmt.Errorf("bedtime.start: %w", err)
		}
		if c.bedEnd, err = parseHM(c.Bedtime.End); err != nil {
			return fmt.Errorf("bedtime.end: %w", err)
		}
		if c.bedStart == c.bedEnd {
			return errors.New("bedtime.start and bedtime.end must differ")
		}
	}
	for _, list := range []struct {
		name    string
		domains []string
	}{{"blocked_domains", c.BlockedDomains}, {"allowed_domains", c.AllowedDomains}} {
		for _, domain := range list.domains {
			if strings.TrimSpace(domain) != domain {
				return fmt.Errorf("%s: invalid domain %q", list.name, domain)
			}
			domain = strings.TrimSuffix(domain, ".")
			if !validDomainName(domain) {
				return fmt.Errorf("%s: invalid domain %q", list.name, domain)
			}
		}
	}
	return nil
}

func validDomainName(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

func parseHM(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, fmt.Errorf("%q: want HH:MM", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

// InBedtime reports whether now falls inside the bedtime window.
func (c *Config) InBedtime(now time.Time) bool {
	if c.Bedtime == nil {
		return false
	}
	t := now.In(c.loc)
	m := t.Hour()*60 + t.Minute()
	if c.bedStart <= c.bedEnd {
		return m >= c.bedStart && m < c.bedEnd
	}
	return m >= c.bedStart || m < c.bedEnd // overnight
}

// Store holds the active config. Readers never block writers.
type Store struct {
	mu sync.Mutex
	p  atomic.Pointer[Config]
}

func (s *Store) Get() *Config {
	c := s.p.Load()
	if c == nil {
		return nil
	}
	copy := *c
	copy.UpstreamDoH = append([]string(nil), c.UpstreamDoH...)
	copy.BlockedServices = append([]string(nil), c.BlockedServices...)
	copy.BlockedDomains = append([]string(nil), c.BlockedDomains...)
	copy.AllowedDomains = append([]string(nil), c.AllowedDomains...)
	if c.Bedtime != nil {
		window := *c.Bedtime
		copy.Bedtime = &window
	}
	return &copy
}

// Set validates and copies c before publishing it. A bad update leaves the
// previously active configuration untouched.
func (s *Store) Set(c *Config) error {
	if c == nil {
		return errors.New("config must not be nil")
	}
	copy := *c
	copy.UpstreamDoH = append([]string(nil), c.UpstreamDoH...)
	copy.BlockedServices = append([]string(nil), c.BlockedServices...)
	copy.BlockedDomains = append([]string(nil), c.BlockedDomains...)
	copy.AllowedDomains = append([]string(nil), c.AllowedDomains...)
	if c.Bedtime != nil {
		window := *c.Bedtime
		copy.Bedtime = &window
	}
	if err := copy.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if active := s.p.Load(); active != nil && copy.Version < active.Version {
		return fmt.Errorf("config version downgrade: active version %d, received %d", active.Version, copy.Version)
	}
	s.p.Store(&copy)
	return nil
}
