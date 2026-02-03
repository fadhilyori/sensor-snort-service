package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mata-elang-stable/sensor-snort-service/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// StreamManager wraps gRPC stream and auto-closes it after a timeout.
// It reuses streams to reduce connection overhead and properly cleans up
// goroutines when closing streams.
type StreamManager struct {
	client  pb.SensorServiceClient
	conn    *grpc.ClientConn
	mu      sync.Mutex
	stream  pb.SensorService_StreamDataClient
	timer   *time.Timer
	timeout time.Duration
}

// NewStreamManager creates a new StreamManager with connection pooling and timeout.
func NewStreamManager(server string, port int, certOpts CertOpts, maxMessageSize int, timeout time.Duration) (*StreamManager, error) {
	var creds credentials.TransportCredentials
	var err error

	if certOpts.Insecure {
		creds = insecure.NewCredentials()
	} else {
		creds, err = credentials.NewClientTLSFromFile(certOpts.CertFile, certOpts.ServerName)
		if err != nil {
			return nil, err
		}
	}

	conn, err := grpc.NewClient(
		fmt.Sprintf("%s:%d", server, port),
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxMessageSize*1024*1024),
			grpc.MaxCallSendMsgSize(maxMessageSize*1024*1024),
		),
	)
	if err != nil {
		return nil, err
	}

	return &StreamManager{
		client:  pb.NewSensorServiceClient(conn),
		conn:    conn,
		timeout: timeout,
	}, nil
}

// getStream returns an active stream. If none exists, it creates one.
func (sm *StreamManager) getStream() (pb.SensorService_StreamDataClient, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.stream != nil {
		sm.resetTimerLocked()
		return sm.stream, nil
	}

	log.Infoln("Creating new gRPC stream")

	stream, err := sm.client.StreamData(context.Background())
	if err != nil {
		return nil, err
	}
	sm.stream = stream
	sm.resetTimerLocked()
	return sm.stream, nil
}

// resetTimerLocked resets the inactivity timer. Must be called with mu held.
func (sm *StreamManager) resetTimerLocked() {
	if sm.timer != nil {
		sm.timer.Stop()
	}
	sm.timer = time.AfterFunc(sm.timeout, func() {
		sm.mu.Lock()
		defer sm.mu.Unlock()
		log.Infoln("Stream timeout reached; closing stream properly")
		sm.closeStreamLocked()
	})
}

func (sm *StreamManager) closeStreamLocked() {
	if sm.stream == nil {
		return
	}

	if _, err := sm.stream.CloseAndRecv(); err != nil {
		log.WithField("package", "grpc").Debugf("Stream closed: %v", err)
	}
	sm.stream = nil
}

// SendEvent sends a single event over the stream and resets the timer.
func (sm *StreamManager) SendEvent(event *pb.SensorEvent) error {
	event.EventSentAt = time.Now().UnixMicro()

	stream, err := sm.getStream()
	if err != nil {
		return err
	}

	log.WithField("package", "grpc").Tracef("Sending data to gRPC server: \n\t%v\n", event)

	if err := stream.Send(event); err != nil {
		sm.mu.Lock()
		sm.closeStreamLocked()
		sm.mu.Unlock()
		return err
	}
	return nil
}

// SendBulkEvent sends multiple events and returns total count.
func (sm *StreamManager) SendBulkEvent(ctx context.Context, events []*pb.SensorEvent) (int64, error) {
	totalEvents := int64(0)

	for i := 0; i < len(events); {
		select {
		case <-ctx.Done():
			return totalEvents, ctx.Err()
		default:
			if err := sm.SendEvent(events[i]); err != nil {
				log.WithField("package", "grpc").Warnf("Failed to send event, retrying: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			totalEvents += events[i].EventMetricsCount
			i++
		}
	}

	return totalEvents, nil
}

// Close closes the stream manager and cleans up resources.
func (sm *StreamManager) Close() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.timer != nil {
		sm.timer.Stop()
		sm.timer = nil
	}

	sm.closeStreamLocked()

	if sm.conn != nil {
		if err := sm.conn.Close(); err != nil {
			log.WithField("package", "grpc").Errorf("Failed to close gRPC connection: %v", err)
		}
		sm.conn = nil
	}

	log.WithField("package", "grpc").Infoln("StreamManager closed")
}
