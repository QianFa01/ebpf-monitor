package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"ebpf-monitor-server/model"

	"github.com/gin-gonic/gin"
)

type EventHandler struct {
	store *model.EventStore
	hub   *WSHub
}

func NewEventHandler(store *model.EventStore, hub *WSHub) *EventHandler {
	return &EventHandler{store: store, hub: hub}
}

func (h *EventHandler) PostEvents(c *gin.Context) {
	raw, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	var events []model.Event
	if err := json.Unmarshal(raw, &events); err != nil {
		var single model.Event
		if err2 := json.Unmarshal(raw, &single); err2 != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
			return
		}
		events = []model.Event{single}
	}
	h.store.AddBatch(events)
	for _, e := range events {
		data, err := json.Marshal(e)
		if err != nil { continue }
		h.hub.Broadcast(data)
	}
	c.JSON(http.StatusOK, gin.H{"accepted": len(events)})
}

func (h *EventHandler) GetEvents(c *gin.Context) {
	category := c.Query("category")
	eventType := c.Query("type")
	pidStr := c.Query("pid")
	sinceStr := c.Query("since")
	limitStr := c.DefaultQuery("limit", "1000")
	var pid uint32
	if pidStr != "" {
		if p, err := strconv.ParseUint(pidStr, 10, 32); err == nil { pid = uint32(p) }
	}
	var since uint64
	if sinceStr != "" {
		if s, err := strconv.ParseUint(sinceStr, 10, 64); err == nil { since = s }
	}
	limit := 1000
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 { limit = l }
	events := h.store.Query(category, eventType, pid, since, limit)
	c.JSON(http.StatusOK, events)
}

func (h *EventHandler) GetStats(c *gin.Context) {
	stats := h.store.Stats(h.hub.ClientCount())
	c.JSON(http.StatusOK, stats)
}

func (h *EventHandler) HandleGetRecent(c *gin.Context) {
	events := h.store.Query("", "", 0, 0, 100)
	c.JSON(http.StatusOK, gin.H{"events": events, "total": len(events)})
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
