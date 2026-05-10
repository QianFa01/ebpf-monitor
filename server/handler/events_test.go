package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ebpf-monitor-server/model"

	"github.com/gin-gonic/gin"
)

func setupTestHandler() (*EventHandler, *model.EventStore, *WSHub) {
	gin.SetMode(gin.TestMode)
	store := model.NewEventStore(1000)
	hub := NewWSHub()
	handler := NewEventHandler(store, hub)
	return handler, store, hub
}

func TestPostEvents_ArrayPayload(t *testing.T) {
	handler, _, _ := setupTestHandler()

	events := []model.Event{
		{Category: "process", EventType: "fork", PID: 1, Timestamp: 100},
		{Category: "network", EventType: "connect", PID: 2, Timestamp: 200},
	}
	body, _ := json.Marshal(events)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/events", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.PostEvents(c)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["accepted"] != float64(2) {
		t.Errorf("accepted = %v, want 2", resp["accepted"])
	}
}

func TestPostEvents_SinglePayload(t *testing.T) {
	handler, store, _ := setupTestHandler()

	event := model.Event{Category: "process", EventType: "fork", PID: 100, Timestamp: 1000}
	body, _ := json.Marshal(event)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/events", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.PostEvents(c)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (single event should be accepted)", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["accepted"] != float64(1) {
		t.Errorf("accepted = %v, want 1", resp["accepted"])
	}

	events := store.Query("", "", 0, 0, 0)
	if len(events) != 1 {
		t.Errorf("store has %d events, want 1", len(events))
	}
}

func TestPostEvents_InvalidJSON(t *testing.T) {
	handler, _, _ := setupTestHandler()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/events", bytes.NewReader([]byte("not json")))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.PostEvents(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestPostEvents_EmptyArray(t *testing.T) {
	handler, _, _ := setupTestHandler()

	body, _ := json.Marshal([]model.Event{})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/events", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.PostEvents(c)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestGetEvents_NoParams(t *testing.T) {
	handler, store, _ := setupTestHandler()

	store.Add(model.Event{Category: "process", EventType: "fork", PID: 1, Timestamp: 100})
	store.Add(model.Event{Category: "network", EventType: "connect", PID: 2, Timestamp: 200})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/events", nil)

	handler.GetEvents(c)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var events []model.Event
	json.Unmarshal(w.Body.Bytes(), &events)
	if len(events) != 2 {
		t.Errorf("events count = %d, want 2", len(events))
	}
}

func TestGetEvents_WithFilters(t *testing.T) {
	handler, store, _ := setupTestHandler()

	store.Add(model.Event{Category: "process", EventType: "fork", PID: 1, Timestamp: 100})
	store.Add(model.Event{Category: "network", EventType: "connect", PID: 2, Timestamp: 200})
	store.Add(model.Event{Category: "process", EventType: "exec", PID: 1, Timestamp: 300})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/events?category=process", nil)

	handler.GetEvents(c)

	var events []model.Event
	json.Unmarshal(w.Body.Bytes(), &events)
	if len(events) != 2 {
		t.Errorf("events count = %d, want 2 (filtered by category)", len(events))
	}
}

func TestGetStats(t *testing.T) {
	handler, store, _ := setupTestHandler()

	store.Add(model.Event{Category: "process", EventType: "fork", PID: 1})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/stats", nil)

	handler.GetStats(c)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var stats model.Stats
	json.Unmarshal(w.Body.Bytes(), &stats)
	if stats.TotalEvents != 1 {
		t.Errorf("TotalEvents = %d, want 1", stats.TotalEvents)
	}
}
