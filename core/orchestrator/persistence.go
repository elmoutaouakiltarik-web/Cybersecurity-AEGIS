package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// EventStore persists events to an append-only JSONL file so they survive
// orchestrator restarts. A nil *EventStore is a safe no-op.
type EventStore struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// OpenEventStore creates or opens the JSONL event log at path.
// Returns nil (no persistence) when path is empty.
func OpenEventStore(path string) (*EventStore, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &EventStore{file: f, path: path}, nil
}

// Append writes one event as a JSON line. Safe to call concurrently.
func (s *EventStore) Append(event SecurityEvent) {
	if s == nil {
		return
	}
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("event store marshal: %v", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.file.Write(append(data, '\n')); err != nil {
		log.Printf("event store write: %v", err)
	}
}

// LoadRecent reads the persisted log and returns at most limit events
// from the tail (most recent). Silently returns nil when path is missing.
func (s *EventStore) LoadRecent(limit int) []SecurityEvent {
	if s == nil {
		return nil
	}
	f, err := os.Open(s.path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var events []SecurityEvent
	scanner := bufio.NewScanner(f)
	// Allow lines up to 1 MB (raw JSON with RawData fields can be large)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		var ev SecurityEvent
		if json.Unmarshal(scanner.Bytes(), &ev) == nil {
			events = append(events, ev)
		}
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events
}

// Close flushes and closes the underlying file. Safe to call on nil.
func (s *EventStore) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.file.Close(); err != nil {
		log.Printf("event store close: %v", err)
	}
}
