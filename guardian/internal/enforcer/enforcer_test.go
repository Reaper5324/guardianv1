package enforcer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"guardian/internal/config"
)

type fakeAdapters struct {
	items []Adapter
	sets  []string
	err   error
}

func (f *fakeAdapters) ListAdapters(context.Context) ([]Adapter, error) {
	return f.items, f.err
}

func (f *fakeAdapters) SetDNS(_ context.Context, id, family string, servers []string) error {
	f.sets = append(f.sets, id+":"+family)
	for i := range f.items {
		if f.items[i].ID != id {
			continue
		}
		if family == "IPv4" {
			f.items[i].IPv4DNS = append([]string(nil), servers...)
		} else {
			f.items[i].IPv6DNS = append([]string(nil), servers...)
		}
	}
	return nil
}

type fakeFirewall struct {
	rules   []Rule
	changed bool
	removed bool
}

func (f *fakeFirewall) ReconcileFirewall(_ context.Context, rules []Rule) (bool, error) {
	f.rules = append([]Rule(nil), rules...)
	changed := f.changed
	f.changed = false
	return changed, nil
}

func (f *fakeFirewall) RemoveFirewall(context.Context, string) error {
	f.removed = true
	return nil
}

type fakePolicies struct {
	changed bool
	removed bool
}

func (f *fakePolicies) ReconcileBrowserPolicies(context.Context) (bool, error) {
	changed := f.changed
	f.changed = false
	return changed, nil
}

func (f *fakePolicies) RemoveBrowserPolicies(context.Context) error {
	f.removed = true
	return nil
}

type fakeState struct {
	value   State
	saved   bool
	removed bool
}

func (f *fakeState) Load() (State, error) {
	if f.value.Adapters == nil && !f.saved {
		return State{}, os.ErrNotExist
	}
	return f.value, nil
}

func (f *fakeState) Save(state State) error {
	f.value = state
	f.saved = true
	return nil
}

func (f *fakeState) Remove() error {
	f.removed = true
	return nil
}

func TestReconcileCapturesAndEnforcesOriginalDNS(t *testing.T) {
	adapter := &fakeAdapters{items: []Adapter{
		{ID: "wifi-1", Name: "Wi-Fi", Up: true, IPv4DNS: []string{"192.0.2.53"}, IPv6DNS: []string{"2001:db8::53"}},
		{ID: "disabled", Name: "Ethernet", Up: false, IPv4DNS: []string{"192.0.2.54"}},
	}}
	fw := &fakeFirewall{changed: true}
	policies := &fakePolicies{changed: true}
	state := &fakeState{}
	var emitted []string
	r := &Reconciler{
		Adapters: adapter,
		Firewall: fw,
		Policies: policies,
		State:    state,
		Emit:     func(message string) { emitted = append(emitted, message) },
	}
	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1:53"

	drift, err := r.Reconcile(context.Background(), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 5 {
		t.Fatalf("drift count = %d, want five: %v", len(drift), drift)
	}
	if got := adapter.items[0].IPv4DNS; len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("IPv4 DNS = %v, want loopback", got)
	}
	if got := adapter.items[0].IPv6DNS; len(got) != 1 || got[0] != "::1" {
		t.Fatalf("IPv6 DNS = %v, want loopback", got)
	}
	if len(adapter.sets) != 2 || len(emitted) != len(drift) {
		t.Fatalf("set calls=%v emitted=%v drift=%v", adapter.sets, emitted, drift)
	}
	original := state.value.Adapters["wifi-1"]
	if original.IPv4DNS[0] != "192.0.2.53" || original.IPv6DNS[0] != "2001:db8::53" {
		t.Fatalf("original DNS not preserved: %+v", original)
	}

	drift, err = r.Reconcile(context.Background(), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 0 {
		t.Fatalf("second reconcile reported drift: %v", drift)
	}
}

func TestReconcilePersistsOriginalsBeforeApplyingDNS(t *testing.T) {
	adapter := &fakeAdapters{items: []Adapter{{ID: "wifi", Up: true}}}
	state := &failingState{}
	r := &Reconciler{
		Adapters: adapter,
		Firewall: &fakeFirewall{},
		Policies: &fakePolicies{},
		State:    state,
	}
	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1:53"
	if _, err := r.Reconcile(context.Background(), &cfg); err == nil {
		t.Fatal("Reconcile succeeded when original DNS state could not be persisted")
	}
	if len(adapter.sets) != 0 {
		t.Fatalf("DNS was changed before saving restore state: %v", adapter.sets)
	}
}

type failingState struct{}

func (failingState) Load() (State, error) { return State{}, os.ErrNotExist }
func (failingState) Save(State) error     { return errors.New("disk full") }
func (failingState) Remove() error        { return nil }

func TestDesiredFirewallRulesExemptConfiguredUpstreams(t *testing.T) {
	cfg := config.Default()
	cfg.UpstreamDoH = []string{"https://1.1.1.1/dns-query", "https://[2606:4700:4700::1111]/dns-query"}
	rules, err := DesiredFirewallRules(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.RemotePort == "443" && (rule.RemoteAddress == "1.1.1.1" || rule.RemoteAddress == "2606:4700:4700::1111") {
			t.Errorf("configured upstream %s is blocked by rule %s", rule.RemoteAddress, rule.Name)
		}
	}
	for _, name := range []string{"DNS-UDP-53", "DNS-TCP-53", "DNS-TCP-853", "VPN-WireGuard-UDP-51820", "VPN-L2TP-UDP-1701"} {
		found := false
		for _, rule := range rules {
			if rule.Name == name {
				found = true
			}
		}
		if !found {
			t.Errorf("missing rule %q", name)
		}
	}
}

func TestFileStateStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := FileStateStore{Path: path}
	want := State{Adapters: map[string]OriginalDNS{
		"adapter": {Name: "Wi-Fi", IPv4DNS: []string{"192.0.2.1"}, IPv6DNS: []string{"2001:db8::1"}},
	}}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Adapters["adapter"].Name != "Wi-Fi" || got.Adapters["adapter"].IPv4DNS[0] != "192.0.2.1" {
		t.Fatalf("state = %+v", got)
	}
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Load succeeded after state removal")
	}
}
