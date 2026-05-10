package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"ebpf-monitor-server/handler"
	"ebpf-monitor-server/model"

	"github.com/gin-gonic/gin"
)

//go:embed static/dist/*
var staticFiles embed.FS

func main() {
	port := flag.Int("port", 8000, "Server port")
	storeSize := flag.Int("store-size", 10000, "Event store capacity")
	flag.Parse()

	log.Printf("=== eBPF Monitor Web Server ===")
	log.Printf("Port: %d", *port)
	log.Printf("Store capacity: %d events", *storeSize)

	store := model.NewEventStore(*storeSize)
	hub := handler.NewWSHub()
	eventHandler := handler.NewEventHandler(store, hub)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(corsMiddleware())

	api := r.Group("/api")
	{
		api.POST("/events", eventHandler.PostEvents)
		api.GET("/events", eventHandler.GetEvents)
		api.GET("/stats", eventHandler.GetStats)
	}

	r.GET("/ws", hub.HandleWebSocket)

	staticFS, err := fs.Sub(staticFiles, "static/dist")
	if err != nil {
		log.Printf("Warning: could not load embedded static files: %v", err)
		log.Printf("Frontend will not be served. Build frontend first: cd frontend && npm run build")
	} else {
		r.GET("/", func(c *gin.Context) {
			data, err := staticFS.(fs.ReadFileFS).ReadFile("index.html")
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "frontend not built"})
				return
			}
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
		})
		r.GET("/assets/*filepath", func(c *gin.Context) {
			filePath := "assets" + c.Param("filepath")
			data, err := fs.ReadFile(staticFS.(fs.ReadFileFS), filePath)
			if err != nil {
				c.Status(http.StatusNotFound)
				return
			}
			contentType := "application/octet-stream"
			switch {
			case len(filePath) > 3 && filePath[len(filePath)-3:] == ".js":
				contentType = "application/javascript"
			case len(filePath) > 4 && filePath[len(filePath)-4:] == ".css":
				contentType = "text/css"
			case len(filePath) > 4 && filePath[len(filePath)-4:] == ".svg":
				contentType = "image/svg+xml"
			}
			c.Data(http.StatusOK, contentType, data)
		})
	}

	r.NoRoute(func(c *gin.Context) {
		if staticFS != nil {
			data, err := staticFS.(fs.ReadFileFS).ReadFile("index.html")
			if err == nil {
				c.Data(http.StatusOK, "text/html; charset=utf-8", data)
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Server listening on %s", addr)
	log.Printf("Dashboard: http://localhost%s", addr)
	log.Printf("WebSocket: ws://localhost%s/ws", addr)

	if err := r.Run(addr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
