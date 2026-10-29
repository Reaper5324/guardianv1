//go:build windows

package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/sys/windows/svc/eventlog"
)

const eventSource = "Guardian"

type WindowsEventSink struct {
	log *eventlog.Log
}

func OpenWindowsEventLog() (*WindowsEventSink, error) {
	log, err := eventlog.Open(eventSource)
	if err != nil {
		return nil, fmt.Errorf("open Guardian event log source: %w", err)
	}
	return &WindowsEventSink{log: log}, nil
}

func InstallWindowsEventLog() error {
	if existing, err := eventlog.Open(eventSource); err == nil {
		return existing.Close()
	}
	if err := eventlog.InstallAsEventCreate(eventSource, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return fmt.Errorf("install Guardian event log source: %w", err)
	}
	return nil
}

func RemoveWindowsEventLog() error {
	if existing, err := eventlog.Open(eventSource); err != nil {
		return nil
	} else if err := existing.Close(); err != nil {
		return err
	}
	if err := eventlog.Remove(eventSource); err != nil {
		return fmt.Errorf("remove Guardian event log source: %w", err)
	}
	return nil
}

func (s *WindowsEventSink) Emit(_ context.Context, event Event) error {
	if s == nil || s.log == nil {
		return errors.New("Windows event log is not open")
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode Windows event: %w", err)
	}
	if err := s.log.Info(1, string(data)); err != nil {
		return fmt.Errorf("write Windows event log: %w", err)
	}
	return nil
}

func (s *WindowsEventSink) Close() error {
	if s == nil || s.log == nil {
		return nil
	}
	err := s.log.Close()
	s.log = nil
	if err != nil {
		return fmt.Errorf("close Windows event log: %w", err)
	}
	return nil
}
