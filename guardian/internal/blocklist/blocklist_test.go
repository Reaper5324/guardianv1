package blocklist

import "testing"

func TestBlockedSuffixAndAllowlist(t *testing.T) {
	m := New([]string{"Example.com", "blocked.test"}, []string{"safe.example.com"})
	tests := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"notexample.com", false},
		{"safe.example.com", false},
		{"child.safe.example.com", false},
		{"blocked.test", true},
		{"unrelated.test", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Blocked(tt.name); got != tt.want {
				t.Errorf("Blocked(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
