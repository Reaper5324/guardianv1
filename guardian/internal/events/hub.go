package events

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

const (
	maxPendingEvents = queueSize * 2
	maxEventMessage  = 2048
)

type Hub struct {
	queue       chan Event
	sinks       []EventSink
	status      *statusFile
	window      time.Duration
	dropped     atomic.Uint64
	OnSinkError func(error)
}

func NewHub(status *statusFile, window time.Duration, sinks ...EventSink) (*Hub, error) {
	if status == nil {
		return nil, errors.New("status store must not be nil")
	}
	if window <= 0 {
		return nil, errors.New("deduplication window must be positive")
	}
	for _, sink := range sinks {
		if sink == nil {
			return nil, errors.New("event sink must not be nil")
		}
	}
	return &Hub{
		queue:  make(chan Event, queueSize),
		sinks:  append([]EventSink(nil), sinks...),
		status: status,
		window: window,
	}, nil
}

func (h *Hub) Record(event Event) bool {
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	if len(event.Message) > maxEventMessage {
		event.Message = event.Message[:maxEventMessage]
	}
	if event.RepeatCount == 0 {
		event.RepeatCount = 1
	}
	select {
	case h.queue <- event:
		return true
	default:
		h.dropped.Add(1)
		return false
	}
}

func (h *Hub) CountBlocked(category string) bool {
	return h.Record(Event{Type: "blocked-hit-count", Category: category})
}

func (h *Hub) Run(ctx context.Context) error {
	ticker := time.NewTicker(h.window)
	defer ticker.Stop()
	pending := make(map[string]Event, maxPendingEvents)
	var sinkErrors []error
	flush := func() {
		for key, event := range pending {
			delete(pending, key)
			if err := h.dispatch(ctx, event); err != nil {
				sinkErrors = append(sinkErrors, err)
				if h.OnSinkError != nil {
					h.OnSinkError(err)
				}
			}
		}
		if dropped := h.dropped.Swap(0); dropped > 0 {
			event := Event{Time: time.Now(), Type: "events-dropped", RepeatCount: dropped}
			if err := h.dispatch(ctx, event); err != nil {
				sinkErrors = append(sinkErrors, err)
				if h.OnSinkError != nil {
					h.OnSinkError(err)
				}
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return errors.Join(sinkErrors...)
		case event := <-h.queue:
			key := event.Type + "\x00" + event.Category + "\x00" + event.Message
			if existing, ok := pending[key]; ok {
				existing.RepeatCount += event.RepeatCount
				pending[key] = existing
				continue
			}
			if len(pending) >= maxPendingEvents {
				h.dropped.Add(event.RepeatCount)
				continue
			}
			pending[key] = event
		case <-ticker.C:
			flush()
		}
	}
}

func (h *Hub) dispatch(ctx context.Context, event Event) error {
	var failures []error
	for _, sink := range h.sinks {
		if err := sink.Emit(ctx, event); err != nil {
			failures = append(failures, err)
		}
	}
	if err := h.status.update(event); err != nil {
		failures = append(failures, fmt.Errorf("write status: %w", err))
	}
	return errors.Join(failures...)
}
