//go:build windows

package main

import "testing"

func TestServiceDashboardReady(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "enforcement active",
			body: `{"listen_addr":"127.0.0.1:53","dns_listeners_ready":true,"firewall_rule_count":8,"firewall_status":"Rules active","can_repair":true,"adapters":[{"up":true,"ipv4_dns":["127.0.0.1"],"ipv6_dns":["::1"]}]}`,
			want: true,
		},
		{
			name: "no active adapter",
			body: `{"listen_addr":"127.0.0.1:53","dns_listeners_ready":true,"firewall_rule_count":8,"can_repair":true,"adapters":[]}`,
			want: true,
		},
		{
			name: "wrong port",
			body: `{"listen_addr":"127.0.0.1:5353","dns_listeners_ready":true,"firewall_rule_count":8,"firewall_status":"Rules active","can_repair":true}`,
		},
		{
			name: "listeners not ready",
			body: `{"listen_addr":"127.0.0.1:53","dns_listeners_ready":false,"firewall_rule_count":8,"firewall_status":"Rules active","can_repair":true}`,
		},
		{
			name: "firewall missing",
			body: `{"listen_addr":"127.0.0.1:53","dns_listeners_ready":true,"firewall_rule_count":0,"firewall_status":"No Guardian rules found","can_repair":true}`,
		},
		{
			name: "adapter DNS not enforced",
			body: `{"listen_addr":"127.0.0.1:53","dns_listeners_ready":true,"firewall_rule_count":8,"firewall_status":"Rules active","can_repair":true,"adapters":[{"up":true,"ipv4_dns":["192.0.2.1"],"ipv6_dns":["::1"]}]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, reason, err := serviceDashboardReady([]byte(test.body))
			if err != nil {
				t.Fatalf("check readiness: %v", err)
			}
			if got != test.want {
				t.Fatalf("readiness = %t (%s), want %t", got, reason, test.want)
			}
			if !got && reason == "" {
				t.Fatal("expected readiness failure reason")
			}
		})
	}
}

func TestServiceDashboardReadyRejectsInvalidJSON(t *testing.T) {
	if _, _, err := serviceDashboardReady([]byte(`{"listen_addr":`)); err == nil {
		t.Fatal("expected invalid status JSON to fail")
	}
}
