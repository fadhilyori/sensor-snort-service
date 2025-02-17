package main

import (
	"context"
	"fmt"
	"github.com/mata-elang-stable/sensor-snort-service/internal/listener"
	"github.com/mata-elang-stable/sensor-snort-service/internal/prometheus_exporter"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	mainContext, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	prom := prometheus_exporter.NewMetrics()

	go prom.StartServer(mainContext)

	socketPath := "/var/log/snort/snort_alert"

	l, err := listener.NewSocketListener(socketPath)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	fmt.Printf("Unix socket listening on %s\n", socketPath)

	if err := l.Serve(handleConnection); err != nil {
		log.Fatalf("Error serving connections: %v", err)
	}
}

// handleConnection processes each connection. In this example, it echoes back data.
func handleConnection(conn net.Conn) {
	defer conn.Close()
	//if _, err := io.Copy(conn, conn); err != nil {
	//	log.Printf("Error handling connection: %v", err)
	//}

	// Read the incoming connection into a buffer
	data, err := io.ReadAll(conn)
	if err != nil {
		log.Println("Error reading:", err.Error())
		return
	}
	fmt.Printf("Received %d bytes: %s\n", len(data), string(data))
}
