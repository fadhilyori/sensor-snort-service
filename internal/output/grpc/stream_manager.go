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

// StreamManager wraps your gRPC stream and auto-closes it after a timeout.
type StreamManager struct {
	client  pb.SensorServiceClient
	mu      sync.Mutex
	stream  pb.SensorService_StreamDataClient
	timer   *time.Timer
	timeout time.Duration
}

// NewStreamManager creates a new StreamManager.
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
		timeout: timeout,
	}, nil
}

// getStream returns an active stream. If none exists, it creates one.
func (sm *StreamManager) getStream() (pb.SensorService_StreamDataClient, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.stream != nil {
		sm.resetTimer() // Reset the timeout on activity.
		return sm.stream, nil
	}

	log.Infoln("Reconnecting to stream")

	stream, err := sm.client.StreamData(context.Background())
	if err != nil {
		return nil, err
	}
	sm.stream = stream
	sm.resetTimer()
	return sm.stream, nil
}

// resetTimer resets the inactivity timer.
func (sm *StreamManager) resetTimer() {
	if sm.timer != nil {
		sm.timer.Stop()
	}
	sm.timer = time.AfterFunc(sm.timeout, func() {
		sm.mu.Lock()
		defer sm.mu.Unlock()
		log.Println("Timeout reached; closing stream")
		if sm.stream != nil {
			if err := sm.stream.CloseSend(); err != nil {
				log.Errorln("Failed to close stream on timeout:", err)
			}
			sm.stream = nil
		}
	})
}

// SendEvent sends an event over the stream and resets the timer.
func (sm *StreamManager) SendEvent(event *pb.SensorEvent) error {
	stream, err := sm.getStream()
	if err != nil {
		return err
	}
	if err := stream.Send(event); err != nil {
		// If sending fails, close the stream so that it will be reestablished next time.
		sm.mu.Lock()
		sm.stream = nil
		sm.mu.Unlock()
		return err
	}
	return nil
}

func (sm *StreamManager) SendBulkEvent(ctx context.Context, events []*pb.SensorEvent) (int64, error) {
	totalEvents := int64(0)

	for i := 0; i < len(events); {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
			if err := sm.SendEvent(events[i]); err != nil {
				continue
			}

			totalEvents += events[i].EventMetricsCount
			i++
		}
	}

	return totalEvents, nil
}

func (sm *StreamManager) Close() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.stream != nil {
		if err := sm.stream.CloseSend(); err != nil {
			log.Errorln("Failed to close stream:", err)
		}
		sm.stream = nil
	}
}
