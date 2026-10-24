package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealth(t *testing.T) {
	o := NewOrchestrator(nil, nil, &Config{MaxEvents: 100})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	res := httptest.NewRecorder()

	o.Routes().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if body["status"] != "healthy" {
		t.Fatalf("unexpected status: %v", body["status"])
	}
	if body["product"] != "Cybersecurity-AEGIS" {
		t.Fatalf("unexpected product: %v", body["product"])
	}
}

func TestDashboardRoute(t *testing.T) {
	o := NewOrchestrator(nil, nil, &Config{MaxEvents: 100})
	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	res := httptest.NewRecorder()

	o.Routes().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	if !bytes.Contains(res.Body.Bytes(), []byte("Cybersecurity-AEGIS")) {
		t.Fatalf("dashboard response does not contain product name")
	}
}

func TestGenericEventIngest(t *testing.T) {
	o := NewOrchestrator(nil, nil, &Config{MaxEvents: 100})
	payload := []byte(`{"source":"unit","category":"test","severity":"high","title":"test event"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/generic", bytes.NewReader(payload))
	res := httptest.NewRecorder()

	o.Routes().ServeHTTP(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", res.Code, res.Body.String())
	}
	events := o.eventBus.Recent(10, "test")
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", events[0].Severity)
	}
}

func TestCyberShieldAIIngest(t *testing.T) {
	o := NewOrchestrator(nil, nil, &Config{MaxEvents: 100})
	payload := []byte(`{"binary_prediction":"ATTACK","family_prediction":"DoS","risk_score":95,"confidence":0.98}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/cybershield-ai", bytes.NewReader(payload))
	res := httptest.NewRecorder()

	o.Routes().ServeHTTP(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", res.Code, res.Body.String())
	}
	events := o.eventBus.Recent(10, "ml")
	if len(events) != 1 {
		t.Fatalf("expected one ML event, got %d", len(events))
	}
	if events[0].Source != "cybershield_ai" {
		t.Fatalf("unexpected source: %s", events[0].Source)
	}
	if events[0].Severity != SeverityCritical {
		t.Fatalf("expected critical severity, got %s", events[0].Severity)
	}
	if events[0].MITRE == nil || events[0].MITRE.TechniqueID != "T1499" {
		t.Fatalf("expected DoS MITRE mapping, got %#v", events[0].MITRE)
	}
}

func TestSuricataNormalization(t *testing.T) {
	raw := map[string]any{
		"alert": map[string]any{
			"signature": "ET TEST Critical alert",
			"severity":  float64(1),
		},
	}
	event := finalizeEvent(normalizeSuricata(raw))
	if event.Source != "suricata" {
		t.Fatalf("unexpected source: %s", event.Source)
	}
	if event.Category != "network" {
		t.Fatalf("unexpected category: %s", event.Category)
	}
	if event.Severity != SeverityCritical {
		t.Fatalf("unexpected severity: %s", event.Severity)
	}
}

func TestWazuhNormalization(t *testing.T) {
	raw := map[string]any{
		"rule": map[string]any{
			"level":       float64(12),
			"description": "Privilege escalation attempt",
			"mitre": map[string]any{
				"id":        "T1068",
				"technique": "Exploitation for Privilege Escalation",
			},
		},
	}
	event := finalizeEvent(normalizeWazuh(raw))
	if event.Severity != SeverityHigh {
		t.Fatalf("unexpected severity: %s", event.Severity)
	}
	if event.MITRE == nil || event.MITRE.TechniqueID != "T1068" {
		t.Fatalf("MITRE mapping missing: %#v", event.MITRE)
	}
}

func TestAuthMiddleware(t *testing.T) {
	o := NewOrchestrator(nil, nil, &Config{MaxEvents: 100})
	auth := NewAuthMiddleware("test-secret-key")
	handler := auth.Wrap(o.Routes())

	// Public endpoints must be reachable without a key.
	for _, path := range []string{"/health", "/dashboard/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code == http.StatusUnauthorized {
			t.Errorf("public endpoint %s rejected without key", path)
		}
	}

	// Protected endpoint without key → 401.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without key, got %d", res.Code)
	}

	// Protected endpoint with correct key → 200.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-secret-key")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid key, got %d", res.Code)
	}

	// Query-parameter key also accepted.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/metrics?api_key=test-secret-key", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 with api_key query param, got %d", res.Code)
	}
}

func TestLocalAuthCreatesLoopbackSession(t *testing.T) {
	o := NewOrchestrator(nil, nil, &Config{MaxEvents: 100})
	auth := NewAuthMiddleware("test-secret-key")
	handler := auth.Wrap(o.Routes())

	// Default: passwordless loopback login must be DISABLED (403).
	t.Setenv("AEGIS_LOCAL_LOGIN", "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local", nil)
	req.RemoteAddr = "127.0.0.1:49152"
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("expected local auth 403 when disabled by default, got %d body=%s", res.Code, res.Body.String())
	}

	// Opt-in via AEGIS_LOCAL_LOGIN=true: loopback session issued.
	t.Setenv("AEGIS_LOCAL_LOGIN", "true")
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/local", nil)
	req.RemoteAddr = "127.0.0.1:49152"
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected local auth 200, got %d body=%s", res.Code, res.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	sid, _ := body["session_token"].(string)
	if sid == "" {
		t.Fatalf("local auth did not return session token: %#v", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	req.Header.Set("X-AEGIS-SESSION", sid)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected metrics 200 with local session, got %d body=%s", res.Code, res.Body.String())
	}
}

func TestLocalAuthRejectsNonLoopback(t *testing.T) {
	o := NewOrchestrator(nil, nil, &Config{MaxEvents: 100})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local", nil)
	req.RemoteAddr = "203.0.113.10:49152"
	res := httptest.NewRecorder()
	o.Routes().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("expected non-loopback local auth 403, got %d", res.Code)
	}
}

func TestEventsTimeline(t *testing.T) {
	o := NewOrchestrator(nil, nil, &Config{MaxEvents: 100})
	payload := []byte(`{"source":"unit","category":"test","severity":"critical","title":"timeline test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/generic", bytes.NewReader(payload))
	res := httptest.NewRecorder()
	o.Routes().ServeHTTP(res, req)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/events/stats/timeline", nil)
	res = httptest.NewRecorder()
	o.Routes().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if body["buckets"] == nil {
		t.Fatal("missing buckets field")
	}
}

func TestEventResolve(t *testing.T) {
	o := NewOrchestrator(nil, nil, &Config{MaxEvents: 100})
	payload := []byte(`{"source":"unit","category":"test","severity":"high","title":"resolve me"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/generic", bytes.NewReader(payload))
	res := httptest.NewRecorder()
	o.Routes().ServeHTTP(res, req)

	var event map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &event); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	id, _ := event["id"].(string)
	if id == "" {
		t.Fatal("event missing id")
	}

	req = httptest.NewRequest(http.MethodPatch, "/api/v1/events/"+id+"/resolve", nil)
	res = httptest.NewRecorder()
	o.Routes().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}

	// Event should now be resolved.
	events := o.eventBus.Recent(10, "test")
	if len(events) == 0 || !events[0].Resolved {
		t.Fatal("event not marked as resolved")
	}
}

func TestEventsExport(t *testing.T) {
	o := NewOrchestrator(nil, nil, &Config{MaxEvents: 100})
	payload := []byte(`{"source":"unit","category":"export","severity":"low","title":"export test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/generic", bytes.NewReader(payload))
	res := httptest.NewRecorder()
	o.Routes().ServeHTTP(res, req)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/events/export", nil)
	res = httptest.NewRecorder()
	o.Routes().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	var events []map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &events); err != nil {
		t.Fatalf("export response is not a JSON array: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("export returned no events")
	}
}

func TestShieldAnalysisDetectsDefensivePatterns(t *testing.T) {
	o := NewOrchestrator(nil, nil, &Config{MaxEvents: 100})
	payloads := [][]byte{
		[]byte(`{"source":"suricata","category":"network","severity":"high","title":"C2 beaconing to 185.220.101.47","description":"Possible command and control callback","raw_data":{"source_ip":"10.2.1.45","destination_ip":"185.220.101.47"},"tags":["c2","beaconing"]}`),
		[]byte(`{"source":"ot_monitor","category":"industrial","severity":"critical","title":"Unauthorized Modbus Write to PLC Coils","description":"Unsafe command message against PLC-PUMP-01","raw_data":{"src_ip":"192.168.100.25","function_code":5},"tags":["ot","modbus","unauthorized"]}`),
	}
	for _, payload := range payloads {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/generic", bytes.NewReader(payload))
		res := httptest.NewRecorder()
		o.Routes().ServeHTTP(res, req)
		if res.Code != http.StatusCreated {
			t.Fatalf("ingest failed: %d %s", res.Code, res.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/shield/analysis?window=24", nil)
	res := httptest.NewRecorder()
	o.Routes().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
	var body ShieldAnalysis
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid shield json: %v", err)
	}
	if body.RiskScore == 0 || len(body.Findings) == 0 {
		t.Fatalf("expected nonzero risk and findings, got score=%d findings=%d", body.RiskScore, len(body.Findings))
	}
	foundOT := false
	foundC2 := false
	for _, f := range body.Findings {
		if f.ID == "ot-unsafe-command" {
			foundOT = true
		}
		if f.ID == "c2-beaconing" {
			foundC2 = true
		}
	}
	if !foundOT || !foundC2 {
		t.Fatalf("expected OT and C2 findings, got %#v", body.Findings)
	}
	if len(body.Hunts) == 0 || len(body.Rules) == 0 || len(body.Actions) == 0 {
		t.Fatalf("expected hunts/rules/actions, got hunts=%d rules=%d actions=%d", len(body.Hunts), len(body.Rules), len(body.Actions))
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	t.TempDir()
	dir := t.TempDir()
	path := dir + "/events.jsonl"

	store, err := OpenEventStore(path)
	if err != nil {
		t.Fatalf("OpenEventStore: %v", err)
	}
	ev := SecurityEvent{
		ID:       "test-001",
		Source:   "unit",
		Category: "test",
		Severity: SeverityHigh,
		Title:    "persist me",
	}
	store.Append(ev)
	store.Close()

	store2, _ := OpenEventStore(path)
	defer store2.Close()
	loaded := store2.LoadRecent(100)
	if len(loaded) != 1 {
		t.Fatalf("expected 1 event, got %d", len(loaded))
	}
	if loaded[0].ID != "test-001" {
		t.Fatalf("unexpected id: %s", loaded[0].ID)
	}
}
