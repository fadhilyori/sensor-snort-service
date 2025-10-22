package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mata-elang-stable/sensor-snort-service/internal/logger"
	"github.com/mata-elang-stable/sensor-snort-service/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var log = logger.GetLogger()
var reconnectMutex sync.Mutex

type Messenger struct {
	ctx            context.Context
	cancel         context.CancelFunc
	creds          credentials.TransportCredentials
	conn           *grpc.ClientConn
	client         pb.SensorServiceClient
	stream         pb.SensorService_StreamDataClient
	server         string
	port           int
	maxRetries     int
	maxMessageSize int
}

type CertOpts struct {
	CertFile   string
	ServerName string
	Insecure   bool
}

// NewGRPCStreamClient creates a new gRPC client that streams data to the server
// Deprecated: Use NewStreamManager instead
func NewGRPCStreamClient(mainCtx context.Context, server string, port int, certOpts CertOpts, maxMessageSize int) (*Messenger, error) {
	ctx, cancel := context.WithCancel(mainCtx)

	m := &Messenger{
		ctx:            ctx,
		cancel:         cancel,
		server:         server,
		port:           port,
		maxRetries:     3,
		maxMessageSize: maxMessageSize,
	}

	if certOpts.Insecure {
		m.creds = insecure.NewCredentials()
	} else {
		creds, err := credentials.NewClientTLSFromFile(certOpts.CertFile, certOpts.ServerName)
		if err != nil {
			return nil, err
		}
		m.creds = creds
	}

	err := m.connect(ctx)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (g *Messenger) connect(_ context.Context) error {
	conn, err := grpc.NewClient(
		fmt.Sprintf("%s:%d", g.server, g.port),
		grpc.WithTransportCredentials(g.creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(g.maxMessageSize*1024*1024),
			grpc.MaxCallSendMsgSize(g.maxMessageSize*1024*1024),
		),
	)
	if err != nil {
		return err
	}

	g.client = pb.NewSensorServiceClient(conn)
	g.conn = conn

	return nil
}

func (g *Messenger) reconnect(ctx context.Context) error {
	reconnectMutex.Lock()
	defer reconnectMutex.Unlock()

	if g.conn != nil {
		state := g.conn.GetState()
		if state == connectivity.Ready {
			return fmt.Errorf("gRPC connection already connected")
		}

		if state == connectivity.Connecting {
			return fmt.Errorf("gRPC connection already connecting")
		}
	}

	if g.maxRetries == 0 {
		return fmt.Errorf("gRPC connection retries exceeded")
	}

	g.closeConn()
	g.maxRetries--

	return g.connect(ctx)
}

func (g *Messenger) StreamData(ctx context.Context, payloads []*pb.SensorEvent) error {
	select {
	case <-ctx.Done():
		log.WithField("package", "grpc").Infoln("Context is done. Stopping the stream.")
		return nil
	default:
		// initialize the stream
		stream, err := g.client.StreamData(ctx)
		if err != nil {
			log.Errorf("Failed to open stream: %v", err)
			return err
		}

		for _, payload := range payloads {
			payload.EventSentAt = time.Now().UnixMicro()

			log.WithField("package", "grpc").Tracef("Sending data to gRPC server: \n\t%v\n", payload)

			// Send the payload to the server
			if err := stream.Send(payload); err != nil {
				return err
			}
		}

		if _, err := stream.CloseAndRecv(); err != nil {
			log.WithField("package", "grpc").Debugf("Stream closed: %v", err)
		}

		return nil
	}
}

func (g *Messenger) closeConn() {
	if err := g.conn.Close(); err != nil {
		log.WithField("package", "grpc").Errorf("Failed to close gRPC connection: %v\n", err)
	}
}

func (g *Messenger) Disconnect() {
	g.closeConn()

	if g.cancel != nil {
		g.cancel()
	}

	log.WithField("package", "grpc").Infoln("Connection to gRPC server is closed.")
}
