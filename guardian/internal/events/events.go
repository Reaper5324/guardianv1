package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	queueSize  = 256
	maxEvents  = 100
	maxBlocked = 366
)

type Event struct {
	Time        time.Time `json:"time"`
	Type        string    `json:"type"`
	Message     string    `json:"message,omitempty"`
	Category    string    `json:"category,omitempty"`
	RepeatCount uint64    `json:"repeat_count,omitempty"`
}

type EventSink interface {
	Emit(context.Context, Event) error
}

type Status struct {
	ServiceStartedAt  time.Time                    `json:"service_started_at"`
	ConfigVersion     uint64                       `json:"config_version"`
	LastRemoteSync    SyncStatus                   `json:"last_remote_sync"`
	LastDrift         DriftStatus                  `json:"last_drift"`
	UpstreamHealth    string                       `json:"upstream_health"`
	Events            []Event                      `json:"events"`
	BlockedHitsPerDay map[string]map[string]uint64 `json:"blocked_hits_per_day"`
}

type SyncStatus struct {
	Result string    `json:"result"`
	Time   time.Time `json:"time,omitempty"`
}

type DriftStatus struct {
	Description string    `json:"description,omitempty"`
	Time        time.Time `json:"time,omitempty"`
}

type statusFile struct {
	path string
	mu   sync.Mutex
	data Status
}

func OpenStatus(path string) (*statusFile, error) {
	s := &statusFile{path: path, data: Status{
		Events:            make([]Event, 0, maxEvents),
		BlockedHitsPerDay: make(map[string]map[string]uint64),
	}}
	raw, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("decode status file: %w", err)
		}
		if s.data.Events == nil {
			s.data.Events = make([]Event, 0, maxEvents)
		}
		if s.data.BlockedHitsPerDay == nil {
			s.data.BlockedHitsPerDay = make(map[string]map[string]uint64)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read status file: %w", err)
	}
	return s, nil
}

func (s *statusFile) Snapshot() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneStatus(s.data)
}

func (s *statusFile) update(event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch event.Type {
	case "config-applied":
		if version, ok := parseVersion(event.Message); ok {
			s.data.ConfigVersion = version
		}
	case "remote-sync":
		s.data.LastRemoteSync = SyncStatus{Result: event.Message, Time: event.Time}
	case "drift-repaired":
		s.data.LastDrift = DriftStatus{Description: event.Message, Time: event.Time}
	case "upstream-health":
		s.data.UpstreamHealth = event.Message
	case "blocked-hit-count":
		day := event.Time.Format("2006-01-02")
		if s.data.BlockedHitsPerDay[day] == nil {
			s.data.BlockedHitsPerDay[day] = make(map[string]uint64)
		}
		s.data.BlockedHitsPerDay[day][event.Category] += event.RepeatCount
		pruneBlocked(s.data.BlockedHitsPerDay, day)
	}
	s.data.Events = append(s.data.Events, event)
	if len(s.data.Events) > maxEvents {
		s.data.Events = append([]Event(nil), s.data.Events[len(s.data.Events)-maxEvents:]...)
	}
	return s.saveLocked()
}

func (s *statusFile) SetServiceStartedAt(at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.ServiceStartedAt = at
	return s.saveLocked()
}

func (s *statusFile) SetConfigVersion(version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.ConfigVersion = version
	return s.saveLocked()
}

func (s *statusFile) saveLocked() error {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode status: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".guardian-status-*.tmp")
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
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	return nil
}

func pruneBlocked(counts map[string]map[string]uint64, today string) {
	if len(counts) <= maxBlocked {
		return
	}
	oldest := ""
	for day := range counts {
		if day != today && (oldest == "" || day < oldest) {
			oldest = day
		}
	}
	if oldest != "" {
		delete(counts, oldest)
	}
}

func cloneStatus(in Status) Status {
	out := in
	out.Events = append([]Event(nil), in.Events...)
	out.BlockedHitsPerDay = make(map[string]map[string]uint64, len(in.BlockedHitsPerDay))
	for day, counts := range in.BlockedHitsPerDay {
		out.BlockedHitsPerDay[day] = make(map[string]uint64, len(counts))
		for category, count := range counts {
			out.BlockedHitsPerDay[day][category] = count
		}
	}
	return out
}

func parseVersion(message string) (uint64, bool) {
	var version uint64
	if _, err := fmt.Sscanf(message, "version=%d", &version); err != nil {
		return 0, false
	}
	return version, true
}
