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

const maxLogSize = 5 << 20

type RotatingLogSink struct {
	path string
	mu   sync.Mutex
	file *os.File
	size int64
}

func OpenRotatingLog(path string) (*RotatingLogSink, error) {
	if path == "" {
		return nil, errors.New("log path must not be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &RotatingLogSink{path: path, file: file, size: stat.Size()}, nil
}

func (s *RotatingLogSink) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	message := string(data)
	if len(message) > 0 && message[len(message)-1] == '\n' {
		message = message[:len(message)-1]
	}
	if err := s.Emit(context.Background(), Event{
		Time:    time.Now().UTC(),
		Type:    "service-log",
		Message: message,
	}); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (s *RotatingLogSink) Emit(_ context.Context, event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode event log entry: %w", err)
	}
	data = append(data, '\n')
	if int64(len(data)) > maxLogSize {
		return errors.New("event log entry exceeds maximum log size")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		stat, err := file.Stat()
		if err != nil {
			file.Close()
			return err
		}
		s.file, s.size = file, stat.Size()
	}
	if s.size+int64(len(data)) > maxLogSize {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	n, err := s.file.Write(data)
	s.size += int64(n)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("short write to event log")
	}
	return nil
}

func (s *RotatingLogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

func (s *RotatingLogSink) rotate() error {
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			return err
		}
		s.file = nil
	}
	backup := s.path + ".1"
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(s.path, backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	s.file, s.size = file, 0
	return nil
}

type MemorySink struct {
	mu     sync.Mutex
	Events []Event
}

func (s *MemorySink) Emit(_ context.Context, event Event) error {
	s.mu.Lock()
	s.Events = append(s.Events, event)
	s.mu.Unlock()
	return nil
}

func (s *MemorySink) Snapshot() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.Events...)
}
