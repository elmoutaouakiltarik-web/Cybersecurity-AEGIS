package main

import "sync"

// LiveHub broadcasts SecurityEvents to subscribers via non-blocking channels.
type LiveHub struct {
	mu          sync.RWMutex
	subscribers map[chan SecurityEvent]struct{}
}

// NewLiveHub creates a new live event hub.
func NewLiveHub() *LiveHub {
	return &LiveHub{
		subscribers: make(map[chan SecurityEvent]struct{}),
	}
}

// Subscribe registers a new subscriber and returns its receive channel.
func (h *LiveHub) Subscribe() chan SecurityEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan SecurityEvent, 16)
	h.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (h *LiveHub) Unsubscribe(ch chan SecurityEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subscribers, ch)
	close(ch)
}

// Broadcast sends an event to all subscribers. Slow consumers are skipped (non-blocking).
func (h *LiveHub) Broadcast(event SecurityEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subscribers {
		select {
		case ch <- event:
		default:
			// Drop for slow consumers to avoid blocking.
		}
	}
}
