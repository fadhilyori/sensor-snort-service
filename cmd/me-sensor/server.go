package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mata-elang-stable/sensor-snort-service/internal/config"
	"github.com/mata-elang-stable/sensor-snort-service/internal/kafka_producer"
	"github.com/mata-elang-stable/sensor-snort-service/internal/pb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the sensor parser gRPC server.",
	Run:   runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)
	viper.SetEnvPrefix("MES_SERVER")
	viper.AutomaticEnv()

	conf := config.GetConfig()

	serverConfig := conf.Server()
	viper.SetDefault("host", "localhost")
	viper.SetDefault("port", 50051)
	viper.SetDefault("insecure", false)
	viper.SetDefault("max_message_size", 100)
	viper.SetDefault("kafka_brokers", "localhost:9092")
	viper.SetDefault("schema_registry_url", "http://localhost:8081")
	viper.SetDefault("kafka_topic", "sensor_events")

	if err := viper.Unmarshal(&serverConfig); err != nil {
		log.WithField("error", err).Fatalln("Failed to unmarshal configuration.")
	}

	conf.GRPCMaxMsgSize = viper.GetInt("max_message_size")

	flags := serverCmd.PersistentFlags()

	flags.StringVarP(&serverConfig.GRPCHost, "host", "s", serverConfig.GRPCHost,
		"Specifies the host to listen to.")
	flags.IntVarP(&serverConfig.GRPCPort, "port", "p", serverConfig.GRPCPort, "Specifies the gRPC port.")
	flags.BoolVar(&serverConfig.GRPCSecure, "insecure", serverConfig.GRPCSecure, "Specifies whether the connection is secure or not.")
	flags.IntVarP(&conf.GRPCMaxMsgSize, "max-message-size", "m", conf.GRPCMaxMsgSize, "Specifies the maximum message size.")
	flags.StringVar(&serverConfig.SchemaRegistryUrl, "schema-registry-url", serverConfig.SchemaRegistryUrl, "Specifies the schema registry URL.")
	flags.StringVar(&serverConfig.KafkaBrokers, "kafka-broker", serverConfig.KafkaBrokers, "Specifies the Kafka broker to connect to.")
	flags.StringVar(&serverConfig.KafkaTopic, "kafka-topic", serverConfig.KafkaTopic, "Specifies the Kafka topic.")
	flags.CountVarP(&conf.VerboseCount, "verbose", "v", "Increase verbosity of the output.")

	if err := viper.BindPFlags(flags); err != nil {
		log.WithField("error", err).Fatalln("Failed to bind flags.")
	}
}

type server struct {
	pb.UnimplementedSensorServiceServer
	kafkaProducerInstance *kafka_producer.Producer
}

func (s *server) StreamData(stream pb.SensorService_StreamDataServer) error {
	log.Traceln("Waiting for data from client via gRPC stream...")
	currentSessionStreamCount := int64(0)

	for {
		payload, err := stream.Recv()
		if err == io.EOF {
			log.Errorf("EOF received from client via gRPC stream: %v\n", err)
			log.Infof("Received %d events in total from gRPC stream\n", currentSessionStreamCount)
			return stream.SendAndClose(&emptypb.Empty{})
		}
		if err != nil {
			log.Errorf("Failed to receive data from client via gRPC stream: %v\n", err)
			return fmt.Errorf("failed to receive data from client via gRPC stream: %w", err)
		}

		currentTime := time.Now()
		payload.EventReceivedAt = currentTime.UnixMicro()

		// calculate the total events received
		currentSessionStreamCount += payload.EventMetricsCount

		err = s.kafkaProducerInstance.Produce(payload)
		if err != nil {
			log.Errorf("Failed to produce message to Kafka: %v\n", err)
			return err
		}

		// log the received payload
		log.Tracef("Received payload: %v\n", payload)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	confInstance := config.GetConfig()
	confInstance.SetupLogging()

	conf := confInstance.Server()

	log.Infof("Starting server with configuration:")
	log.Infof("Host: %s", conf.GRPCHost)
	log.Infof("Port: %d", conf.GRPCPort)
	log.Infof("Secure: %t", conf.GRPCSecure)
	log.Infof("GRPCMaxMsgSize: %d", confInstance.GRPCMaxMsgSize)
	log.Infof("Kafka broker: %s", conf.KafkaBrokers)
	log.Infof("Schema registry URL: %s", conf.SchemaRegistryUrl)
	log.Infof("Kafka topic: %s", conf.KafkaTopic)
	log.Infoln("")

	// Create a context with cancel function on interrupt signal
	mainContext, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	g, _ := errgroup.WithContext(mainContext)

	// Initialize kafka producer instance
	producer, err := kafka_producer.NewKafkaProducer(conf.KafkaBrokers, conf.SchemaRegistryUrl, conf.KafkaTopic)
	if err != nil {
		log.Fatalf("Failed to create kafka producer: %v", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", conf.GRPCHost, conf.GRPCPort))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(confInstance.GRPCMaxMsgSize*1024*1024),
		grpc.MaxSendMsgSize(confInstance.GRPCMaxMsgSize*1024*1024),
	)
	pb.RegisterSensorServiceServer(grpcServer, &server{
		kafkaProducerInstance: producer,
	})

	g.Go(func() error {
		<-mainContext.Done()

		log.Infoln("Shutting down the server...")
		cancel()
		grpcServer.Stop()
		producer.Flush(15 * 1000)
		producer.Close()

		return nil
	})

	g.Go(func() error {
		defer log.Infoln("Shutting down the gRPC server...")
		log.Println(fmt.Sprintf("Starting gRPC server on %s:%d", conf.GRPCHost, conf.GRPCPort))
		if err := grpcServer.Serve(listener); err != nil {
			return fmt.Errorf("failed to serve: %v", err)
		}

		return nil
	})

	if err := g.Wait(); err != nil {
		log.WithField("error", err).Fatalln("error during execution")
	}
}
