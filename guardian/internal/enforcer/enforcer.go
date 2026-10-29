package enforcer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"guardian/internal/config"
)

const rulePrefix = "Guardian-"

var reconciliationMu sync.Mutex

type Adapter struct {
	ID      string
	Name    string
	Up      bool
	IPv4DNS []string
	IPv6DNS []string
}

type Rule struct {
	Name          string
	Protocol      string
	RemotePort    string
	RemoteAddress string
}

type AdapterBackend interface {
	ListAdapters(context.Context) ([]Adapter, error)
	SetDNS(context.Context, string, string, []string) error
}

type FirewallBackend interface {
	ReconcileFirewall(context.Context, []Rule) (bool, error)
	RemoveFirewall(context.Context, string) error
}

type BrowserPolicyBackend interface {
	ReconcileBrowserPolicies(context.Context) (bool, error)
	RemoveBrowserPolicies(context.Context) error
}

type State struct {
	Adapters map[string]OriginalDNS `json:"adapters"`
}

type OriginalDNS struct {
	Name    string   `json:"name"`
	IPv4DNS []string `json:"ipv4_dns"`
	IPv6DNS []string `json:"ipv6_dns"`
}

type StateStore interface {
	Load() (State, error)
	Save(State) error
	Remove() error
}

type EventFunc func(string)

type Reconciler struct {
	Adapters AdapterBackend
	Firewall FirewallBackend
	Policies BrowserPolicyBackend
	State    StateStore
	Emit     EventFunc
}

func (r *Reconciler) Reconcile(ctx context.Context, cfg *config.Config) ([]string, error) {
	if err := r.validate(cfg); err != nil {
		return nil, err
	}
	reconciliationMu.Lock()
	defer reconciliationMu.Unlock()
	state, err := r.State.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load adapter DNS state: %w", err)
	}
	if state.Adapters == nil {
		state.Adapters = make(map[string]OriginalDNS)
	}

	adapters, err := r.Adapters.ListAdapters(ctx)
	if err != nil {
		return nil, fmt.Errorf("list network adapters: %w", err)
	}
	drift := make([]string, 0)
	active := make([]Adapter, 0, len(adapters))
	for _, adapter := range adapters {
		if !adapter.Up {
			continue
		}
		if adapter.ID == "" {
			return nil, errors.New("network adapter has an empty stable ID")
		}
		if _, ok := state.Adapters[adapter.ID]; !ok {
			state.Adapters[adapter.ID] = OriginalDNS{
				Name:    adapter.Name,
				IPv4DNS: append([]string(nil), adapter.IPv4DNS...),
				IPv6DNS: append([]string(nil), adapter.IPv6DNS...),
			}
			drift = append(drift, "new adapter "+adapter.Name)
		}
		active = append(active, adapter)
	}
	if err := r.State.Save(state); err != nil {
		return nil, fmt.Errorf("persist original adapter DNS: %w", err)
	}

	for _, adapter := range active {
		if !sameDNS(adapter.IPv4DNS, []string{"127.0.0.1"}) {
			if err := r.Adapters.SetDNS(ctx, adapter.ID, "IPv4", []string{"127.0.0.1"}); err != nil {
				return drift, fmt.Errorf("enforce IPv4 DNS on %s: %w", adapter.Name, err)
			}
			drift = append(drift, "IPv4 DNS on "+adapter.Name)
		}
		if !sameDNS(adapter.IPv6DNS, []string{"::1"}) {
			if err := r.Adapters.SetDNS(ctx, adapter.ID, "IPv6", []string{"::1"}); err != nil {
				return drift, fmt.Errorf("enforce IPv6 DNS on %s: %w", adapter.Name, err)
			}
			drift = append(drift, "IPv6 DNS on "+adapter.Name)
		}
	}

	rules, err := DesiredFirewallRules(cfg)
	if err != nil {
		return drift, err
	}
	changed, err := r.Firewall.ReconcileFirewall(ctx, rules)
	if err != nil {
		return drift, fmt.Errorf("reconcile firewall rules: %w", err)
	}
	if changed {
		drift = append(drift, "firewall rules")
	}
	changed, err = r.Policies.ReconcileBrowserPolicies(ctx)
	if err != nil {
		return drift, fmt.Errorf("reconcile browser policies: %w", err)
	}
	if changed {
		drift = append(drift, "browser policies")
	}
	if r.Emit != nil {
		for _, item := range drift {
			r.Emit(item)
		}
	}
	return drift, nil
}

func (r *Reconciler) validate(cfg *config.Config) error {
	if r == nil || r.Adapters == nil || r.Firewall == nil || r.Policies == nil || r.State == nil {
		return errors.New("enforcer dependencies are incomplete")
	}
	if cfg == nil {
		return errors.New("config must not be nil")
	}
	_, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil || port != "53" {
		return errors.New("enforcement requires a DNS listener on port 53")
	}
	return nil
}

func (r *Reconciler) Run(ctx context.Context, getConfig func() *config.Config, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("reconcile interval must be positive")
	}
	if getConfig == nil {
		return errors.New("config provider must not be nil")
	}
	if _, err := r.Reconcile(ctx, getConfig()); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := r.Reconcile(ctx, getConfig()); err != nil {
				return err
			}
		}
	}
}

func (r *Reconciler) Remove(ctx context.Context) error {
	if r == nil || r.Adapters == nil || r.Firewall == nil || r.Policies == nil || r.State == nil {
		return errors.New("enforcer dependencies are incomplete")
	}
	reconciliationMu.Lock()
	defer reconciliationMu.Unlock()
	state, err := r.State.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load adapter DNS state: %w", err)
	}
	var failures []error
	adapters, err := r.Adapters.ListAdapters(ctx)
	if err != nil {
		failures = append(failures, fmt.Errorf("list network adapters: %w", err))
	} else {
		for _, adapter := range adapters {
			original, ok := state.Adapters[adapter.ID]
			if !ok {
				continue
			}
			if err := r.Adapters.SetDNS(ctx, adapter.ID, "IPv4", original.IPv4DNS); err != nil {
				failures = append(failures, fmt.Errorf("restore IPv4 DNS on %s: %w", adapter.Name, err))
			}
			if err := r.Adapters.SetDNS(ctx, adapter.ID, "IPv6", original.IPv6DNS); err != nil {
				failures = append(failures, fmt.Errorf("restore IPv6 DNS on %s: %w", adapter.Name, err))
			}
		}
	}
	if err := r.Firewall.RemoveFirewall(ctx, rulePrefix); err != nil {
		failures = append(failures, fmt.Errorf("remove firewall rules: %w", err))
	}
	if err := r.Policies.RemoveBrowserPolicies(ctx); err != nil {
		failures = append(failures, fmt.Errorf("remove browser policies: %w", err))
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	if err := r.State.Remove(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove adapter DNS state: %w", err)
	}
	return nil
}

func sameDNS(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i := range actual {
		if !strings.EqualFold(strings.TrimSpace(actual[i]), expected[i]) {
			return false
		}
	}
	return true
}

func DesiredFirewallRules(cfg *config.Config) ([]Rule, error) {
	exempt := make(map[string]struct{}, len(cfg.UpstreamDoH))
	for _, raw := range cfg.UpstreamDoH {
		u, err := url.Parse(raw)
		if err != nil || net.ParseIP(u.Hostname()) == nil {
			return nil, fmt.Errorf("invalid IP-literal upstream %q", raw)
		}
		exempt[net.ParseIP(u.Hostname()).String()] = struct{}{}
	}

	rules := []Rule{
		{Name: "DNS-UDP-53", Protocol: "UDP", RemotePort: "53", RemoteAddress: "nonloopback"},
		{Name: "DNS-TCP-53", Protocol: "TCP", RemotePort: "53", RemoteAddress: "nonloopback"},
		{Name: "DNS-TCP-853", Protocol: "TCP", RemotePort: "853", RemoteAddress: "nonloopback"},
		{Name: "VPN-WireGuard-UDP-51820", Protocol: "UDP", RemotePort: "51820", RemoteAddress: "any"},
		{Name: "VPN-OpenVPN-UDP-1194", Protocol: "UDP", RemotePort: "1194", RemoteAddress: "any"},
		{Name: "VPN-OpenVPN-TCP-1194", Protocol: "TCP", RemotePort: "1194", RemoteAddress: "any"},
		{Name: "VPN-IKE-UDP-500", Protocol: "UDP", RemotePort: "500", RemoteAddress: "any"},
		{Name: "VPN-IPsec-UDP-4500", Protocol: "UDP", RemotePort: "4500", RemoteAddress: "any"},
		{Name: "VPN-PPTP-TCP-1723", Protocol: "TCP", RemotePort: "1723", RemoteAddress: "any"},
		{Name: "VPN-L2TP-UDP-1701", Protocol: "UDP", RemotePort: "1701", RemoteAddress: "any"},
	}
	for _, ip := range wellKnownResolverIPs {
		if _, isUpstream := exempt[ip]; isUpstream {
			continue
		}
		port := strconv.Itoa(443)
		rules = append(rules,
			Rule{Name: "DoH-TCP-" + strings.ReplaceAll(ip, ":", "-"), Protocol: "TCP", RemotePort: port, RemoteAddress: ip},
			Rule{Name: "DoH-UDP-" + strings.ReplaceAll(ip, ":", "-"), Protocol: "UDP", RemotePort: port, RemoteAddress: ip},
		)
	}
	return rules, nil
}

var wellKnownResolverIPs = []string{
	"1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2",
	"8.8.8.8", "8.8.4.4",
	"9.9.9.9", "149.112.112.112",
	"94.140.14.14", "94.140.15.15",
	"76.76.2.0", "76.76.10.0",
	"2606:4700:4700::1111", "2606:4700:4700::1001",
	"2001:4860:4860::8888", "2001:4860:4860::8844",
	"2620:fe::fe", "2620:fe::9",
	"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
}

type FileStateStore struct {
	Path string
}

func (s FileStateStore) Load() (State, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("decode adapter DNS state: %w", err)
	}
	if state.Adapters == nil {
		state.Adapters = make(map[string]OriginalDNS)
	}
	return state, nil
}

func (s FileStateStore) Save(state State) error {
	if s.Path == "" {
		return errors.New("state file path must not be empty")
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode adapter DNS state: %w", err)
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".guardian-dns-state-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.Path); err != nil {
		return err
	}
	return nil
}

func (s FileStateStore) Remove() error {
	return os.Remove(s.Path)
}
