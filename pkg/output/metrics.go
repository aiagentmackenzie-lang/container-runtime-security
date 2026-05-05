// Package output - metrics.go
// Prometheus metrics exporter for the SecurityScarlet Runtime agent.

package output

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ── Metrics Exporter ──────────────────────────────────────────────────

// MetricsExporter wraps Prometheus metrics for the runtime agent.
type MetricsExporter struct {
	port int

	// Counters
	alertsTotal      *prometheus.CounterVec
	enforcementTotal *prometheus.CounterVec
	eventsProcessed   *prometheus.CounterVec
	ringBufferEvents  prometheus.Counter
	ringBufferDrops   prometheus.Counter

	// Histograms
	eventLatency  *prometheus.HistogramVec
	enforceLatency *prometheus.HistogramVec
	aiLatency     *prometheus.HistogramVec

	// Gauges
	containersTracked prometheus.Gauge
	rulesLoaded      prometheus.Gauge

	// Internal counters for status
	totalAlerts    atomic.Uint64
	totalEnforce   atomic.Uint64
	totalEvents   atomic.Uint64

	server *http.Server
}

// NewMetricsExporter creates a new Prometheus metrics exporter.
func NewMetricsExporter(port int) *MetricsExporter {
	m := &MetricsExporter{
		port: port,
	}

	const ns = "scarlet"

	// Alert counters
	m.alertsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: ns,
			Name:      "alerts_total",
			Help:      "Total number of alerts emitted by rule and priority.",
		},
		[]string{"rule", "priority", "action"},
	)

	// Enforcement counters
	m.enforcementTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: ns,
			Name:      "enforcement_actions_total",
			Help:      "Total enforcement actions by type and result.",
		},
		[]string{"type", "result"},
	)

	// Event processing counters
	m.eventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: ns,
			Name:      "events_processed_total",
			Help:      "Total events processed by category and disposition.",
		},
		[]string{"disposition", "category"},
	)

	// Ring buffer metrics
	m.ringBufferEvents = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: ns,
			Name:      "ring_buffer_events_total",
			Help:      "Total events read from BPF ring buffer.",
		},
	)
	m.ringBufferDrops = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: ns,
			Name:      "ring_buffer_drops_total",
			Help:      "Total ring buffer drops (backpressure).",
		},
	)

	// Latency histograms
	m.eventLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "event_processing_latency_us",
			Help:      "Event processing latency in microseconds.",
			Buckets:   []float64{10, 50, 100, 250, 500, 1000, 2500, 5000},
		},
		[]string{"category"},
	)
	m.enforceLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "enforcement_latency_us",
			Help:      "Enforcement action latency in microseconds.",
			Buckets:   []float64{10, 50, 100, 200, 500, 1000},
		},
		[]string{"type"},
	)
	m.aiLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "ai_inference_latency_us",
			Help:      "AI inference latency in microseconds.",
			Buckets:   []float64{100, 500, 1000, 5000, 10000, 50000},
		},
		[]string{"model"},
	)

	// Gauges
	m.containersTracked = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "containers_tracked",
			Help:      "Number of containers currently being tracked.",
		},
	)
	m.rulesLoaded = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "rules_loaded",
			Help:      "Number of rules currently loaded.",
		},
	)

	// Register with default registry
	prometheus.MustRegister(
		m.alertsTotal,
		m.enforcementTotal,
		m.eventsProcessed,
		m.ringBufferEvents,
		m.ringBufferDrops,
		m.eventLatency,
		m.enforceLatency,
		m.aiLatency,
		m.containersTracked,
		m.rulesLoaded,
	)

	return m
}

// Start starts the HTTP metrics server.
func (m *MetricsExporter) Start(ctx context.Context) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	m.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", m.port),
		Handler: mux,
	}

	log.Printf("[metrics] Starting Prometheus metrics server on :%d", m.port)

	if err := m.server.ListenAndServe(); err != nil {
		if err != http.ErrServerClosed {
			log.Printf("[metrics] HTTP server error: %v", err)
		}
	}
}

// Stop gracefully stops the metrics server.
func (m *MetricsExporter) Stop() {
	if m.server != nil {
		m.server.Close()
	}
	log.Printf("[metrics] Metrics server stopped. Total alerts: %d, enforcements: %d, events: %d",
		m.totalAlerts.Load(), m.totalEnforce.Load(), m.totalEvents.Load())
}

// ── Recording Methods ────────────────────────────────────────────────

// RecordAlert records an alert in metrics.
func (m *MetricsExporter) RecordAlert(ruleID, priority, action string) {
	m.alertsTotal.WithLabelValues(ruleID, priority, action).Inc()
	m.totalAlerts.Add(1)
}

// RecordEnforcement records an enforcement action in metrics.
func (m *MetricsExporter) RecordEnforcement(actionType, result string) {
	m.enforcementTotal.WithLabelValues(actionType, result).Inc()
	m.totalEnforce.Add(1)
}

// RecordEventProcessed records a processed event.
func (m *MetricsExporter) RecordEventProcessed(disposition, category string) {
	m.eventsProcessed.WithLabelValues(disposition, category).Inc()
	m.totalEvents.Add(1)
	m.ringBufferEvents.Inc()
}

// RecordRuleMatch records a rule match.
func (m *MetricsExporter) RecordRuleMatch(ruleID, action string) {
	// Map to alert or enforcement metric based on action
	switch action {
	case "enforce":
		m.RecordEnforcement("sigkill", "completed")
	case "alert":
		m.RecordAlert(ruleID, "", action)
	case "simulate":
		m.RecordEnforcement("sigkill", "simulated")
	}
}

// RecordRingBufferDrop records a ring buffer drop event.
func (m *MetricsExporter) RecordRingBufferDrop() {
	m.ringBufferDrops.Inc()
}

// SetContainersTracked updates the container tracking gauge.
func (m *MetricsExporter) SetContainersTracked(count int) {
	m.containersTracked.Set(float64(count))
}

// SetRulesLoaded updates the rules loaded gauge.
func (m *MetricsExporter) SetRulesLoaded(count int) {
	m.rulesLoaded.Set(float64(count))
}

