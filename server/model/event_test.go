package model

import (
	"sync"
	"testing"
	"time"
)

func TestNewEventStore(t *testing.T) {
	store := NewEventStore(100)
	if store.capacity != 100 {
		t.Errorf("capacity = %d, want 100", store.capacity)
	}
	if store.totalCount != 0 {
		t.Errorf("totalCount = %d, want 0", store.totalCount)
	}
	if len(store.events) != 0 {
		t.Errorf("events length = %d, want 0", len(store.events))
	}
}

func TestEventStore_Add(t *testing.T) {
	store := NewEventStore(100)
	e := Event{Category: "process", EventType: "fork", PID: 100, Timestamp: 1000}
	store.Add(e)

	if store.totalCount != 1 {
		t.Errorf("totalCount = %d, want 1", store.totalCount)
	}
	if len(store.events) != 1 {
		t.Errorf("events length = %d, want 1", len(store.events))
	}
	if store.byCategory["process"] != 1 {
		t.Errorf("byCategory[process] = %d, want 1", store.byCategory["process"])
	}
	if store.byType["fork"] != 1 {
		t.Errorf("byType[fork] = %d, want 1", store.byType["fork"])
	}
}

func TestEventStore_Add_Overflow(t *testing.T) {
	store := NewEventStore(3)
	for i := 0; i < 5; i++ {
		store.Add(Event{Category: "process", EventType: "fork", PID: uint32(i), Timestamp: uint64(i)})
	}

	if len(store.events) != 3 {
		t.Errorf("events length = %d, want 3", len(store.events))
	}
	if store.totalCount != 5 {
		t.Errorf("totalCount = %d, want 5", store.totalCount)
	}
	if store.events[0].PID != 2 {
		t.Errorf("first event PID = %d, want 2 (oldest evicted)", store.events[0].PID)
	}
}

func TestEventStore_AddBatch(t *testing.T) {
	store := NewEventStore(100)
	events := []Event{
		{Category: "process", EventType: "fork", PID: 1},
		{Category: "network", EventType: "connect", PID: 2},
		{Category: "file", EventType: "create", PID: 3},
	}
	store.AddBatch(events)

	if store.totalCount != 3 {
		t.Errorf("totalCount = %d, want 3", store.totalCount)
	}
	if len(store.events) != 3 {
		t.Errorf("events length = %d, want 3", len(store.events))
	}
}

func TestEventStore_AddBatch_Empty(t *testing.T) {
	store := NewEventStore(100)
	store.AddBatch([]Event{})
	if store.totalCount != 0 {
		t.Errorf("totalCount = %d, want 0", store.totalCount)
	}
}

func TestEventStore_Query_NoFilters(t *testing.T) {
	store := NewEventStore(100)
	store.Add(Event{Category: "process", EventType: "fork", PID: 1, Timestamp: 100})
	store.Add(Event{Category: "network", EventType: "connect", PID: 2, Timestamp: 200})

	result := store.Query("", "", 0, 0, 0)
	if len(result) != 2 {
		t.Errorf("result length = %d, want 2", len(result))
	}
}

func TestEventStore_Query_ByCategory(t *testing.T) {
	store := NewEventStore(100)
	store.Add(Event{Category: "process", EventType: "fork", PID: 1, Timestamp: 100})
	store.Add(Event{Category: "network", EventType: "connect", PID: 2, Timestamp: 200})
	store.Add(Event{Category: "process", EventType: "exec", PID: 3, Timestamp: 300})

	result := store.Query("process", "", 0, 0, 0)
	if len(result) != 2 {
		t.Errorf("result length = %d, want 2", len(result))
	}
	for _, e := range result {
		if e.Category != "process" {
			t.Errorf("unexpected category: %s", e.Category)
		}
	}
}

func TestEventStore_Query_ByType(t *testing.T) {
	store := NewEventStore(100)
	store.Add(Event{Category: "process", EventType: "fork", PID: 1, Timestamp: 100})
	store.Add(Event{Category: "process", EventType: "exec", PID: 2, Timestamp: 200})

	result := store.Query("", "fork", 0, 0, 0)
	if len(result) != 1 {
		t.Errorf("result length = %d, want 1", len(result))
	}
}

func TestEventStore_Query_ByPID(t *testing.T) {
	store := NewEventStore(100)
	store.Add(Event{Category: "process", EventType: "fork", PID: 100, Timestamp: 100})
	store.Add(Event{Category: "process", EventType: "fork", PID: 200, Timestamp: 200})

	result := store.Query("", "", 100, 0, 0)
	if len(result) != 1 {
		t.Errorf("result length = %d, want 1", len(result))
	}
	if result[0].PID != 100 {
		t.Errorf("PID = %d, want 100", result[0].PID)
	}
}

func TestEventStore_Query_BySince(t *testing.T) {
	store := NewEventStore(100)
	store.Add(Event{Category: "process", EventType: "fork", PID: 1, Timestamp: 100})
	store.Add(Event{Category: "process", EventType: "fork", PID: 2, Timestamp: 200})
	store.Add(Event{Category: "process", EventType: "fork", PID: 3, Timestamp: 300})

	result := store.Query("", "", 0, 200, 0)
	if len(result) != 2 {
		t.Errorf("result length = %d, want 2", len(result))
	}
}

func TestEventStore_Query_Limit(t *testing.T) {
	store := NewEventStore(100)
	for i := 0; i < 10; i++ {
		store.Add(Event{Category: "process", EventType: "fork", PID: uint32(i), Timestamp: uint64(i)})
	}

	result := store.Query("", "", 0, 0, 3)
	if len(result) != 3 {
		t.Errorf("result length = %d, want 3", len(result))
	}
}

func TestEventStore_Query_DefaultLimit(t *testing.T) {
	store := NewEventStore(100)
	for i := 0; i < 5; i++ {
		store.Add(Event{Category: "process", EventType: "fork", PID: uint32(i), Timestamp: uint64(i)})
	}

	result := store.Query("", "", 0, 0, 0)
	if len(result) != 5 {
		t.Errorf("result length = %d, want 5 (default limit not reached)", len(result))
	}
}

func TestEventStore_Stats_Empty(t *testing.T) {
	store := NewEventStore(100)
	time.Sleep(10 * time.Millisecond)
	stats := store.Stats(0)

	if stats.TotalEvents != 0 {
		t.Errorf("TotalEvents = %d, want 0", stats.TotalEvents)
	}
	if stats.EventsPerSec != 0 {
		t.Errorf("EventsPerSec = %f, want 0", stats.EventsPerSec)
	}
	if stats.ConnectedClients != 0 {
		t.Errorf("ConnectedClients = %d, want 0", stats.ConnectedClients)
	}
}

func TestEventStore_Stats_WithEvents(t *testing.T) {
	store := NewEventStore(100)
	time.Sleep(10 * time.Millisecond)

	for i := 0; i < 10; i++ {
		store.Add(Event{Category: "process", EventType: "fork", PID: uint32(i)})
	}

	time.Sleep(10 * time.Millisecond)
	stats := store.Stats(5)

	if stats.TotalEvents != 10 {
		t.Errorf("TotalEvents = %d, want 10", stats.TotalEvents)
	}
	if stats.EventsPerSec <= 0 {
		t.Errorf("EventsPerSec = %f, want > 0", stats.EventsPerSec)
	}
	if stats.ConnectedClients != 5 {
		t.Errorf("ConnectedClients = %d, want 5", stats.ConnectedClients)
	}
	if stats.ByCategory["process"] != 10 {
		t.Errorf("ByCategory[process] = %d, want 10", stats.ByCategory["process"])
	}
}

func TestEventStore_Stats_ClientCount(t *testing.T) {
	store := NewEventStore(100)
	stats := store.Stats(42)
	if stats.ConnectedClients != 42 {
		t.Errorf("ConnectedClients = %d, want 42", stats.ConnectedClients)
	}
}

func TestEventStore_Concurrent(t *testing.T) {
	store := NewEventStore(1000)
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				store.Add(Event{
					Category:  "process",
					EventType: "fork",
					PID:       uint32(id*100 + j),
					Timestamp: uint64(j),
				})
			}
		}(i)
	}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				store.Query("process", "", 0, 0, 10)
				store.Stats(0)
			}
		}()
	}

	wg.Wait()

	if store.totalCount != 1000 {
		t.Errorf("totalCount = %d, want 1000", store.totalCount)
	}
}
