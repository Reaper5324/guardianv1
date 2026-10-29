package config

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T, bedtime string) *Config {
	t.Helper()
	text := `{"bedtime":` + bedtime + `,"timezone":"UTC"}`
	c, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c
}

func TestInBedtime(t *testing.T) {
	tests := []struct {
		name string
		win  string
		hour int
		min  int
		day  int
		want bool
	}{
		{"day before start", `{"start":"22:00","end":"23:00"}`, 21, 59, 2, false},
		{"day start included", `{"start":"22:00","end":"23:00"}`, 22, 0, 2, true},
		{"day end excluded", `{"start":"22:00","end":"23:00"}`, 23, 0, 2, false},
		{"overnight start included", `{"start":"22:00","end":"06:00"}`, 22, 0, 2, true},
		{"overnight before midnight", `{"start":"22:00","end":"06:00"}`, 23, 59, 2, true},
		{"overnight midnight", `{"start":"22:00","end":"06:00"}`, 0, 0, 3, true},
		{"overnight end excluded", `{"start":"22:00","end":"06:00"}`, 6, 0, 3, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testConfig(t, tt.win)
			now := time.Date(2025, time.January, tt.day, tt.hour, tt.min, 0, 0, c.loc)
			if got := c.InBedtime(now); got != tt.want {
				t.Errorf("InBedtime(%s) = %v, want %v", now.Format(time.RFC3339), got, tt.want)
			}
		})
	}
}

func TestInBedtimeAcrossDSTAndClockZoneChanges(t *testing.T) {
	cfg, err := Parse([]byte(`{"timezone":"America/New_York","bedtime":{"start":"01:30","end":"03:30"}}`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{
			name: "spring transition before skipped hour",
			now:  time.Date(2025, time.March, 9, 6, 59, 0, 0, time.UTC),
			want: true,
		},
		{
			name: "spring transition after skipped hour",
			now:  time.Date(2025, time.March, 9, 7, 0, 0, 0, time.UTC),
			want: true,
		},
		{
			name: "first repeated fall-back hour",
			now:  time.Date(2025, time.November, 2, 5, 30, 0, 0, time.UTC),
			want: true,
		},
		{
			name: "second repeated fall-back hour",
			now:  time.Date(2025, time.November, 2, 6, 30, 0, 0, time.UTC),
			want: true,
		},
		{
			name: "window end boundary",
			now:  time.Date(2025, time.January, 15, 8, 30, 0, 0, time.UTC),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cfg.InBedtime(tt.now); got != tt.want {
				t.Errorf("InBedtime(%s) = %v, want %v", tt.now.Format(time.RFC3339), got, tt.want)
			}
		})
	}

	localEquivalent := time.Date(2025, time.January, 15, 3, 0, 0, 0, time.FixedZone("changed-system-zone", -5*60*60))
	utcEquivalent := localEquivalent.UTC()
	if got, want := cfg.InBedtime(localEquivalent), cfg.InBedtime(utcEquivalent); got != want {
		t.Errorf("system time-zone representation changed bedtime result: %v != %v", got, want)
	}
}

func TestParseRejectsInvalidConfiguration(t *testing.T) {
	for _, raw := range []string{
		`{"blocked_service":["instagram"]}`,
		`{"blocked_domains":[""]}`,
		`{"allowed_domains":["not a domain"]}`,
		`{"blocked_services":["unknown-service"]}`,
		`{"bedtime":{"start":"22:00","end":"22:00"}}`,
		`{"listen_addr":"0.0.0.0:53"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("Parse succeeded; expected validation error")
			}
		})
	}
}

func TestParseRejectsMalformedDomains(t *testing.T) {
	for _, domain := range []string{
		"bad domain.test",
		"bad..test",
		"-bad.test",
		"bad-.test",
		"bad_name.test",
		strings.Repeat("a", 64) + ".test",
	} {
		t.Run(domain, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"blocked_domains": []string{domain}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(raw); err == nil {
				t.Fatalf("Parse accepted invalid domain %q", domain)
			}
		})
	}
}

func TestParseAcceptsValidDomainWithTrailingDot(t *testing.T) {
	if _, err := Parse([]byte(`{"blocked_domains":["Example.COM."]}`)); err != nil {
		t.Fatalf("Parse rejected valid domain: %v", err)
	}
}

func TestStoreBadUpdatePreservesGoodConfig(t *testing.T) {
	good := testConfig(t, `null`)
	store := &Store{}
	if err := store.Set(good); err != nil {
		t.Fatal(err)
	}
	bad := *good
	bad.ListenAddr = "0.0.0.0:53"
	if err := store.Set(&bad); err == nil {
		t.Fatal("Set accepted invalid config")
	}
	if got := store.Get().ListenAddr; got != good.ListenAddr {
		t.Fatalf("active listen address changed to %q", got)
	}
}

func TestStoreRejectsVersionDowngrade(t *testing.T) {
	store := &Store{}
	current := testConfig(t, `null`)
	current.Version = 8
	if err := store.Set(current); err != nil {
		t.Fatal(err)
	}
	older := testConfig(t, `null`)
	older.Version = 7
	if err := store.Set(older); err == nil {
		t.Fatal("Set accepted a lower config version")
	}
	if got := store.Get().Version; got != 8 {
		t.Fatalf("active version = %d, want 8", got)
	}
}

func TestStoreCommitFailurePreservesActiveConfig(t *testing.T) {
	store := &Store{}
	active := testConfig(t, `null`)
	active.Version = 3
	if err := store.Set(active); err != nil {
		t.Fatal(err)
	}
	next := testConfig(t, `null`)
	next.Version = 4
	next.BlockedDomains = []string{"new.example"}
	if err := store.Update(next, func() error { return errors.New("disk write failed") }); err == nil {
		t.Fatal("Update succeeded despite commit failure")
	}
	got := store.Get()
	if got.Version != active.Version || len(got.BlockedDomains) != 0 {
		t.Fatalf("active config changed after failed commit: %+v", got)
	}
}

func TestParseRejectsTrailingJSON(t *testing.T) {
	if _, err := Parse([]byte(`{} {}`)); err == nil {
		t.Fatal("Parse accepted trailing JSON")
	}
}

func TestParseAcceptsIPv6LoopbackListener(t *testing.T) {
	if _, err := Parse([]byte(`{"listen_addr":"[::1]:53"}`)); err != nil {
		t.Fatalf("Parse rejected IPv6 loopback listener: %v", err)
	}
}
