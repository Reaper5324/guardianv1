package events

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHubDeduplicatesAndUpdatesStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	status, err := OpenStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now().Add(-time.Minute).UTC()
	if err := status.SetServiceStartedAt(started); err != nil {
		t.Fatal(err)
	}
	sink := &MemorySink{}
	hub, err := NewHub(status, 20*time.Millisecond, sink)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- hub.Run(ctx) }()
	for i := 0; i < 3; i++ {
		if !hub.CountBlocked("instagram") {
			t.Fatal("event queue unexpectedly full")
		}
	}
	for i := 0; i < 2; i++ {
		hub.Record(Event{Type: "drift-repaired", Message: "adapter DNS"})
	}
	hub.Record(Event{Type: "config-applied", Message: "version=9"})
	hub.Record(Event{Type: "remote-sync", Message: "success"})

	deadline := time.After(2 * time.Second)
	for len(sink.Snapshot()) < 4 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("events were not flushed")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Hub.Run: %v", err)
	}

	got := status.Snapshot()
	if !got.ServiceStartedAt.Equal(started) {
		t.Errorf("service start = %v, want %v", got.ServiceStartedAt, started)
	}
	if got.ConfigVersion != 9 {
		t.Errorf("config version = %d, want 9", got.ConfigVersion)
	}
	if got.LastRemoteSync.Result != "success" || got.LastRemoteSync.Time.IsZero() {
		t.Errorf("last sync = %+v", got.LastRemoteSync)
	}
	count := got.BlockedHitsPerDay[time.Now().Format("2006-01-02")]["instagram"]
	if count != 3 {
		t.Errorf("blocked hit count = %d, want 3", count)
	}
	if len(got.Events) != 4 {
		t.Errorf("status event count = %d, want 4", len(got.Events))
	}
	for _, event := range got.Events {
		if event.Type == "blocked-hit-count" && event.RepeatCount != 3 {
			t.Errorf("blocked repeat count = %d, want 3", event.RepeatCount)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Status
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.BlockedHitsPerDay[time.Now().Format("2006-01-02")]["instagram"] != 3 {
		t.Fatalf("persisted status lost blocked count: %+v", persisted.BlockedHitsPerDay)
	}
}

func TestRecordIsBoundedAndDoesNotBlock(t *testing.T) {
	status, err := OpenStatus(filepath.Join(t.TempDir(), "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	hub, err := NewHub(status, time.Hour, &MemorySink{})
	if err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for i := 0; i < queueSize+10; i++ {
		if hub.Record(Event{Type: "test"}) {
			accepted++
		}
	}
	if accepted != queueSize || hub.dropped.Load() != 10 {
		t.Fatalf("accepted=%d dropped=%d", accepted, hub.dropped.Load())
	}
}

func TestRotatingLogIsBoundedAndStructured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.log")
	sink, err := OpenRotatingLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if err := sink.Emit(context.Background(), Event{Type: "service-started", Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(context.Background(), Event{Type: "large", Message: strings.Repeat("x", maxLogSize-128)}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(context.Background(), Event{Type: "rotate"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > maxLogSize {
		t.Fatalf("current log size = %d, exceeds %d", info.Size(), maxLogSize)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated log missing: %v", err)
	}
}

func TestRotatingLogWriterEncodesStructuredLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.log")
	sink, err := OpenRotatingLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	message := "guardian listening on 127.0.0.1:53\n"
	if n, err := sink.Write([]byte(message)); err != nil || n != len(message) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(message))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(raw), &event); err != nil {
		t.Fatalf("decode structured log line: %v", err)
	}
	if event.Type != "service-log" || event.Message != strings.TrimSuffix(message, "\n") {
		t.Fatalf("log event = %+v", event)
	}
}
