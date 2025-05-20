package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/viper"

	// _ "net/http/pprof"

	"github.com/mata-elang-stable/sensor-snort-service/internal/output/grpc"

	"github.com/mata-elang-stable/sensor-snort-service/internal/prometheus_exporter"
	"golang.org/x/sync/errgroup"

	"github.com/mata-elang-stable/sensor-snort-service/internal/config"
	"github.com/mata-elang-stable/sensor-snort-service/internal/listener"
	"github.com/mata-elang-stable/sensor-snort-service/internal/queue"
	"github.com/spf13/cobra"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Run the sensor parser client.",
	Run:   runClient,
}

func init() {
	rootCmd.AddCommand(clientCmd)
	viper.SetEnvPrefix("MES_CLIENT")
	viper.AutomaticEnv()

	conf := config.GetConfig()

	clientConfig := conf.Client()
	viper.SetDefault("file", "/var/log/snort/alert_json.txt")
	viper.SetDefault("server", "localhost")
	viper.SetDefault("port", 50051)
	viper.SetDefault("insecure", true)
	viper.SetDefault("interval", 1*time.Second)
	viper.SetDefault("sensor_id", "sensor1")
	viper.SetDefault("testing_mode", false)
	viper.SetDefault("max_clients", 10)
	viper.SetDefault("max_message_size", 100)

	if err := viper.Unmarshal(&clientConfig); err != nil {
		log.WithField("error", err).Fatalln("Failed to unmarshal configuration.")
	}

	conf.GRPCMaxMsgSize = viper.GetInt("max_message_size")

	flags := clientCmd.PersistentFlags()

	flags.StringVarP(&clientConfig.SnortAlertFile, "file", "f", clientConfig.SnortAlertFile,
		"Specifies the path to the Snort alert file.")
	flags.StringVarP(&clientConfig.GRPCServer, "server", "s", clientConfig.GRPCServer, "Specifies the gRPC server.")
	flags.IntVarP(&clientConfig.GRPCPort, "port", "p", clientConfig.GRPCPort, "Specifies the gRPC port.")
	flags.BoolVar(&clientConfig.GRPCSecure, "insecure", clientConfig.GRPCSecure, "Specifies whether the connection is secure or not.")
	flags.CountVarP(&conf.VerboseCount, "verbose", "v", "Increase verbosity of the output.")
	flags.StringVar(&clientConfig.SensorID, "sensor-id", clientConfig.SensorID, "Specifies the sensor ID.")
	flags.DurationVarP(&clientConfig.GRPCInterval, "interval", "i", clientConfig.GRPCInterval, "Specifies the interval to send the data to the server.")
	flags.BoolVarP(&clientConfig.TestingMode, "testing-mode", "t", clientConfig.TestingMode, "Specifies whether the application is running in testing mode. Testing mode will activate insecure connection and skip the gRPC server name verification.")
	flags.IntVarP(&clientConfig.MaxClients, "max-clients", "k", clientConfig.MaxClients, "Specifies the maximum number of clients.")
	flags.IntVarP(&conf.GRPCMaxMsgSize, "max-message-size", "m", conf.GRPCMaxMsgSize, "Specifies the maximum message size.")

	if err := viper.BindPFlags(flags); err != nil {
		log.WithField("error", err).Fatalln("Failed to bind flags.")
	}
}

func runClient(cmd *cobra.Command, args []string) {
	// Load the configuration
	confInstance := config.GetConfig()
	confInstance.SetupLogging()

	conf := confInstance.Client()

	log.Infof("Starting server with configuration:")
	log.Infof("SnortAlertFile: %s", conf.SnortAlertFile)
	log.Infof("GRPCServer: %s", conf.GRPCServer)
	log.Infof("GRPCPort: %d", conf.GRPCPort)
	log.Infof("GRPCSecure: %t", conf.GRPCSecure)
	log.Infof("GRPCInterval: %s", conf.GRPCInterval)
	log.Infof("SensorID: %s", conf.SensorID)
	log.Infof("TestingMode: %t", conf.TestingMode)
	log.Infof("MaxClients: %d", conf.MaxClients)
	log.Infof("GRPCMaxMsgSize: %d", confInstance.GRPCMaxMsgSize)
	log.Infof("")

	// Create a context with cancel function on interrupt signal
	mainContext, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Create a file listener
	fileListener, err := listener.NewFileListener(conf.SnortAlertFile)
	if err != nil {
		log.WithField("error", err).Fatalln("failed to create file listener")
		return
	}

	// Create an event queue to store sensor events
	eventQueue := queue.NewEventBatchQueue()

	streamManager, err := grpc.NewStreamManager(conf.GRPCServer, conf.GRPCPort, grpc.CertOpts{Insecure: true}, confInstance.GRPCMaxMsgSize, 10*time.Second)
	if err != nil {
		log.Errorf("Failed to create stream manager: %v", err)
	}

	// Prometheus exporter is used to expose metrics to Prometheus
	// The metrics are used to monitor the application
	prom := prometheus_exporter.NewMetrics()

	// Create a wait group to wait for all goroutines to finish
	g, gCtx := errgroup.WithContext(mainContext)

	// Start the event queue watcher
	g.Go(func() error {
		defer cancel()
		log.Infof("Starting Watcher...")
		err := eventQueue.StartWatcher(gCtx, streamManager)
		defer log.WithField("package", "main").Infof("Watcher Job is stopped. (%v)\n", err)
		return err
	})

	// Start the file listener
	g.Go(func() error {
		defer cancel()
		log.Infof("Starting File Listener...")
		err := fileListener.Start(gCtx, eventQueue)
		defer log.WithField("package", "main").Infof("File Listener Job is stopped. (%v)\n", err)
		return err
	})

	// Start the prometheus exporter server
	g.Go(func() error {
		log.Infof("Starting Prometheus Exporter Server...")
		err := prom.StartServer(gCtx)
		log.WithField("package", "main").Infof("Prometheus Exporter Job is stopped. (%v)\n", err)
		return err
	})

	// Handle the main context cancellation
	g.Go(func() error {
		defer cancel()
		<-mainContext.Done()
		log.Infof("Shutting down the client...")

		streamManager.Close()
		return fileListener.Stop()
	})

	// Record metrics every second using the prometheus exporter
	g.Go(func() error {
		ticker := time.NewTicker(10 * time.Second)
		defer func() {
			ticker.Stop()
			log.Infoln("Metrics recorder is stopped.")
		}()

		log.Infof("Starting metrics recorder...")

		for {
			select {
			case <-gCtx.Done():
				log.Infoln("Metrics recorder is stopping...")
				log.Infoln("Canceling the context...")
				cancel()
				return nil
			case <-ticker.C:
				prom.RecordMetrics(fileListener, eventQueue)
			}
		}
	})

	// Wait for all goroutines to finish
	if err := g.Wait(); err != nil {
		log.WithField("error", err).Fatalln("failed to start the application")
		return
	}
}
