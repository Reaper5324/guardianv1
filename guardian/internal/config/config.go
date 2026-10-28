// Package config defines Guardian's configuration, validates it, and holds
// the active copy behind an atomic pointer so it can be hot-swapped.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
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
	c := Default()
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
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
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("listen_addr: %w", err)
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
	}
	return nil
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
type Store struct{ p atomic.Pointer[Config] }

func (s *Store) Get() *Config  { return s.p.Load() }
func (s *Store) Set(c *Config) { s.p.Store(c) }
