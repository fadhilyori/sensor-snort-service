package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mata-elang-stable/sensor-snort-service/internal/listener"
	"github.com/mata-elang-stable/sensor-snort-service/internal/prometheus_exporter"
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
func handleConnection(data []byte) {
	// fmt.Printf("Received bytes: %x\n", data)
	parsedData, err := listener.ParseAlertPacket(data)
	if err != nil {
		log.Printf("Error parsing data: %v", err)
		return
	}

	// fmt.Printf("Alert message: %s\n", parsedData.AlertMsg)
	// fmt.Printf("Parsed data: %+v\n", parsedData)
	listener.ParseRawPacket(parsedData.Pkt)
}
