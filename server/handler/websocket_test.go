package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func setupWSTestServer(hub *WSHub) *httptest.Server {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ws", hub.HandleWebSocket)
	return httptest.NewServer(r)
}

func TestNewWSHub(t *testing.T) {
	hub := NewWSHub()
	if hub == nil {
		t.Fatal("NewWSHub returned nil")
	}
	if hub.ClientCount() != 0 {
		t.Errorf("ClientCount = %d, want 0", hub.ClientCount())
	}
}

func TestWSHub_Broadcast_NoClients(t *testing.T) {
	hub := NewWSHub()
	msg := []byte(`{"type":"process"}`)
	hub.Broadcast(msg)
}

func TestWSHub_Broadcast_WithClients(t *testing.T) {
	hub := NewWSHub()
	server := setupWSTestServer(hub)
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):]
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"/ws", nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	if hub.ClientCount() != 1 {
		t.Errorf("ClientCount = %d, want 1", hub.ClientCount())
	}

	msg := []byte(`{"type":"process","data":{"pid":1}}`)
	hub.Broadcast(msg)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, received, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	var event map[string]interface{}
	if err := json.Unmarshal(received, &event); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if event["type"] != "process" {
		t.Errorf("received type = %v, want process", event["type"])
	}
}

func TestWSHub_ClientDisconnect(t *testing.T) {
	hub := NewWSHub()
	server := setupWSTestServer(hub)
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):]
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"/ws", nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	if hub.ClientCount() != 1 {
		t.Errorf("ClientCount = %d, want 1", hub.ClientCount())
	}

	conn.Close()
	time.Sleep(100 * time.Millisecond)

	if hub.ClientCount() != 0 {
		t.Errorf("ClientCount = %d, want 0 after disconnect", hub.ClientCount())
	}
}

func TestHandleWebSocket_InvalidRequest(t *testing.T) {
	hub := NewWSHub()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ws", hub.HandleWebSocket)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ws", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for non-websocket request", w.Code)
	}
	if hub.ClientCount() != 0 {
		t.Errorf("ClientCount = %d, want 0 after failed upgrade", hub.ClientCount())
	}
}
