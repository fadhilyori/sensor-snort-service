package prometheus_exporter

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/mata-elang-stable/sensor-snort-service/internal/listener"
	"github.com/mata-elang-stable/sensor-snort-service/internal/logger"
	"github.com/mata-elang-stable/sensor-snort-service/internal/queue"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	MESEventReadPerSecond = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mataelang_sensor_event_read_per_second",
		Help: "Number of events read per second from Snort3 JSON File.",
	})
	MESEventProcessedPerSecond = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mataelang_sensor_event_processed_per_second",
		Help: "Number of events processed per second.",
	})
	MESEventBatchSentPerSecond = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mataelang_sensor_event_batch_sent_per_second",
		Help: "Number of batch events sent per second.",
	})
	MESBatchQueueSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mataelang_sensor_batch_queue_size",
		Help: "Size of the batch queue.",
	})
	MESBatchQueueEventSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mataelang_sensor_batch_queue_event_size",
		Help: "Size of the event queued in the batch queue.",
	})
	MESTotalProcessedEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mataelang_sensor_total_processed_events",
		Help: "Total number of processed events.",
	})
	MESTotalSentEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mataelang_sensor_total_sent_events",
		Help: "Total number of sent events.",
	})
)

var log = logger.GetLogger()

type Metrics struct {
	reg *prometheus.Registry
}

func NewMetrics() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
	}

	m.reg.MustRegister(
		MESEventReadPerSecond,
		MESEventProcessedPerSecond,
		MESEventBatchSentPerSecond,
		MESBatchQueueSize,
		MESBatchQueueEventSize,
		MESTotalProcessedEvents,
		MESTotalSentEvents,
	)

	m.reg.MustRegister(collectors.NewGoCollector())
	m.reg.MustRegister(collectors.NewBuildInfoCollector())
	m.reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	return m
}

func (prom *Metrics) StartServer(ctx context.Context) error {
	server := &http.Server{
		Addr: ":9101",
		ReadHeaderTimeout: time.Second * 5,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/metrics" {
				promhttp.HandlerFor(
					prom.reg, promhttp.HandlerOpts{
						EnableOpenMetrics: false,
						Registry:          prom.reg,
					}).ServeHTTP(w, r)
			} else {
				http.NotFound(w, r)
			}
		}),
	}

	go func() {
		<-ctx.Done()

		ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctxShutDown); err != nil {
			log.Errorln("Failed to gracefully shutdown the server", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func (prom *Metrics) RecordMetrics(fileListener *listener.FileListener, eventQueue *queue.EventBatchQueue) {
	MESEventReadPerSecond.Set(float64(fileListener.GetEventReadPerSecond()))
	MESEventProcessedPerSecond.Set(float64(eventQueue.GetEventProcessedPerSecond()))
	MESEventBatchSentPerSecond.Set(float64(eventQueue.GetEventBatchSentPerSecond()))
	MESBatchQueueSize.Set(float64(eventQueue.GetQueueSize()))
	MESBatchQueueEventSize.Set(float64(eventQueue.GetEventQueueSize()))
	MESTotalProcessedEvents.Add(float64(eventQueue.GetTotalProcessedEvents()))
	MESTotalSentEvents.Add(float64(eventQueue.GetTotalSentEvents()))
}
