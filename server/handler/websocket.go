package handler

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type WSHub struct {
	mu      sync.RWMutex
	clients map[*WSClient]bool
}

type WSClient struct {
	hub  *WSHub
	conn *websocket.Conn
	send chan []byte
}

func NewWSHub() *WSHub {
	return &WSHub{clients: make(map[*WSClient]bool)}
}

func (h *WSHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *WSHub) Broadcast(message []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for client := range h.clients {
		select {
		case client.send <- message:
		default:
		}
	}
}

func (h *WSHub) HandleWebSocket(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	client := &WSClient{hub: h, conn: conn, send: make(chan []byte, 256)}
	h.mu.Lock()
	h.clients[client] = true
	h.mu.Unlock()
	log.Printf("WebSocket client connected (total: %d)", h.ClientCount())
	go client.writePump()
	go client.readPump()
}

func (c *WSClient) readPump() {
	defer func() {
		c.hub.mu.Lock()
		delete(c.hub.clients, c)
		c.hub.mu.Unlock()
		c.conn.Close()
		log.Printf("WebSocket client disconnected (total: %d)", c.hub.ClientCount())
	}()
	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil { break }
	}
}

func (c *WSClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() { ticker.Stop(); c.conn.Close() }()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil { return }
			w.Write(message)
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte("\n"))
				w.Write(<-c.send)
			}
			if err := w.Close(); err != nil { return }
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil { return }
		}
	}
}
