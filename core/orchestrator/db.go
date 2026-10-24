package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"github.com/lib/pq"
)

// DBStore manages PostgreSQL persistence for security events.
// A nil *DBStore safely disables DB persistence.
type DBStore struct {
	db *sql.DB
}

// NewDBStore opens a PostgreSQL connection, verifies it, and ensures the schema.
// If connString is empty or the DB is unreachable, it returns nil (in-memory fallback).
func NewDBStore(connString string) *DBStore {
	if connString == "" {
		return nil
	}
	db, err := sql.Open("postgres", connString)
	if err != nil {
		log.Printf("WARNING: could not open PostgreSQL: %v (running without DB)", err)
		return nil
	}
	if err := db.Ping(); err != nil {
		log.Printf("WARNING: PostgreSQL ping failed: %v (running without DB)", err)
		_ = db.Close()
		return nil
	}
	store := &DBStore{db: db}
	if err := store.ensureSchema(); err != nil {
		log.Printf("WARNING: PostgreSQL schema init failed: %v (running without DB)", err)
		_ = db.Close()
		return nil
	}
	log.Printf("PostgreSQL persistence enabled")
	return store
}

func (s *DBStore) ensureSchema() error {
	const schema = `
CREATE TABLE IF NOT EXISTS security_events (
	id TEXT PRIMARY KEY,
	timestamp TIMESTAMPTZ NOT NULL,
	source TEXT NOT NULL,
	category TEXT NOT NULL,
	severity TEXT NOT NULL,
	title TEXT NOT NULL,
	description TEXT,
	raw_json JSONB,
	mitre_json JSONB,
	ot_json JSONB,
	resolved BOOLEAN DEFAULT FALSE,
	tags TEXT[]
)`
	_, err := s.db.Exec(schema)
	return err
}

// Insert persists a single event. Safe to call on nil.
func (s *DBStore) Insert(event SecurityEvent) error {
	if s == nil || s.db == nil {
		return nil
	}
	rawJSON, _ := json.Marshal(event.RawData)
	var mitreJSON []byte
	if event.MITRE != nil {
		mitreJSON, _ = json.Marshal(event.MITRE)
	}
	var otJSON []byte
	if event.OTContext != nil {
		otJSON, _ = json.Marshal(event.OTContext)
	}
	_, err := s.db.Exec(`
		INSERT INTO security_events (id, timestamp, source, category, severity, title, description, raw_json, mitre_json, ot_json, resolved, tags)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (id) DO NOTHING`,
		event.ID, event.Timestamp, event.Source, event.Category, string(event.Severity), event.Title, event.Description,
		rawJSON, mitreJSON, otJSON, event.Resolved, pq.Array(event.Tags),
	)
	if err != nil {
		log.Printf("db insert error: %v", err)
	}
	return err
}

// Recent returns the most recent events, optionally filtered by category.
func (s *DBStore) Recent(limit int, category string) ([]SecurityEvent, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if category != "" {
		rows, err = s.db.Query(`
			SELECT id, timestamp, source, category, severity, title, description, raw_json, mitre_json, ot_json, resolved, tags
			FROM security_events
			WHERE category = $1
			ORDER BY timestamp DESC
			LIMIT $2`, category, limit)
	} else {
		rows, err = s.db.Query(`
			SELECT id, timestamp, source, category, severity, title, description, raw_json, mitre_json, ot_json, resolved, tags
			FROM security_events
			ORDER BY timestamp DESC
			LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// Count24h returns total, critical, and high event counts for the last 24 hours.
func (s *DBStore) Count24h() (total int64, critical int64, high int64, err error) {
	if s == nil || s.db == nil {
		return 0, 0, 0, nil
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	err = s.db.QueryRow(`
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE severity = 'critical'),
		       COUNT(*) FILTER (WHERE severity = 'high')
		FROM security_events
		WHERE timestamp >= $1`, cutoff).Scan(&total, &critical, &high)
	return total, critical, high, err
}

func scanEvents(rows *sql.Rows) ([]SecurityEvent, error) {
	var events []SecurityEvent
	for rows.Next() {
		var ev SecurityEvent
		var rawJSON, mitreJSON, otJSON []byte
		var tags []string
		var severity string
		err := rows.Scan(
			&ev.ID, &ev.Timestamp, &ev.Source, &ev.Category, &severity, &ev.Title, &ev.Description,
			&rawJSON, &mitreJSON, &otJSON, &ev.Resolved, pq.Array(&tags),
		)
		if err != nil {
			return nil, err
		}
		ev.Severity = Severity(severity)
		ev.Tags = tags
		if len(rawJSON) > 0 {
			_ = json.Unmarshal(rawJSON, &ev.RawData)
		}
		if len(mitreJSON) > 0 {
			ev.MITRE = &MITREAttack{}
			_ = json.Unmarshal(mitreJSON, ev.MITRE)
		}
		if len(otJSON) > 0 {
			ev.OTContext = &OTContext{}
			_ = json.Unmarshal(otJSON, ev.OTContext)
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}
