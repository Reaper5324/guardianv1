package config

import (
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

func TestParseRejectsInvalidConfiguration(t *testing.T) {
	for _, raw := range []string{
		`{"blocked_service":["instagram"]}`,
		`{"blocked_domains":[""]}`,
		`{"allowed_domains":["not a domain"]}`,
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

func TestParseRejectsTrailingJSON(t *testing.T) {
	if _, err := Parse([]byte(`{} {}`)); err == nil {
		t.Fatal("Parse accepted trailing JSON")
	}
}
