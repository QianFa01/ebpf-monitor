package model

import (
	"sync"
	"time"
)

type Event struct {
	Timestamp     uint64                 `json:"timestamp"`
	Category      string                 `json:"category"`
	EventType     string                 `json:"event_type"`
	PID           uint32                 `json:"pid"`
	PPID          uint32                 `json:"ppid"`
	UID           uint32                 `json:"uid"`
	GID           uint32                 `json:"gid"`
	Comm          string                 `json:"comm"`
	ContainerID   string                 `json:"container_id"`
	ContainerName string                 `json:"container_name"`
	Filename      string                 `json:"filename,omitempty"`
	OldFilename   string                 `json:"old_filename,omitempty"`
	ExitCode      uint32                 `json:"exit_code,omitempty"`
	Mode          uint32                 `json:"mode,omitempty"`
	Flags         uint32                 `json:"flags,omitempty"`
	OldUID        uint32                 `json:"old_uid,omitempty"`
	SrcAddr       string                 `json:"src_addr,omitempty"`
	DstAddr       string                 `json:"dst_addr,omitempty"`
	SrcPort       uint16                 `json:"src_port,omitempty"`
	DstPort       uint16                 `json:"dst_port,omitempty"`
	Protocol      uint8                  `json:"protocol,omitempty"`
	WriteBytes    uint32                 `json:"write_bytes,omitempty"`
	Extra         map[string]interface{} `json:"extra,omitempty"`
}

type Stats struct {
	TotalEvents      uint64            `json:"total_events"`
	EventsPerSec     float64           `json:"events_per_sec"`
	ByCategory       map[string]uint64 `json:"by_category"`
	ByType           map[string]uint64 `json:"by_type"`
	ConnectedClients int               `json:"connected_clients"`
	LastEventTime    time.Time         `json:"last_event_time"`
}

type EventStore struct {
	mu         sync.RWMutex
	events     []Event
	capacity   int
	totalCount uint64
	byCategory map[string]uint64
	byType     map[string]uint64
	lastTime   time.Time
}

func NewEventStore(capacity int) *EventStore {
	return &EventStore{
		events:     make([]Event, 0, capacity),
		capacity:   capacity,
		byCategory: make(map[string]uint64),
		byType:     make(map[string]uint64),
	}
}

func (s *EventStore) Add(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= s.capacity {
		s.events = s.events[1:]
	}
	s.events = append(s.events, e)
	s.totalCount++
	s.byCategory[e.Category]++
	s.byType[e.EventType]++
	s.lastTime = time.Now()
}

func (s *EventStore) AddBatch(events []Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range events {
		if len(s.events) >= s.capacity {
			s.events = s.events[1:]
		}
		s.events = append(s.events, e)
		s.totalCount++
		s.byCategory[e.Category]++
		s.byType[e.EventType]++
	}
	s.lastTime = time.Now()
}

func (s *EventStore) Query(category, eventType string, pid uint32, since uint64, limit int) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 { limit = 1000 }
	result := make([]Event, 0, limit)
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if category != "" && e.Category != category { continue }
		if eventType != "" && e.EventType != eventType { continue }
		if pid != 0 && e.PID != pid { continue }
		if since != 0 && e.Timestamp < since { continue }
		result = append(result, e)
		if len(result) >= limit { break }
	}
	return result
}

func (s *EventStore) Stats(clientCount int) Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	byCat := make(map[string]uint64)
	byTyp := make(map[string]uint64)
	for k, v := range s.byCategory { byCat[k] = v }
	for k, v := range s.byType { byTyp[k] = v }
	var eps float64
	if !s.lastTime.IsZero() {
		elapsed := time.Since(s.lastTime).Seconds()
		if elapsed > 0 && elapsed < 60 { eps = float64(s.totalCount) / elapsed }
	}
	return Stats{
		TotalEvents: s.totalCount, EventsPerSec: eps,
		ByCategory: byCat, ByType: byTyp,
		ConnectedClients: clientCount, LastEventTime: s.lastTime,
	}
}
