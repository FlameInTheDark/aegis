package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics bundles the platform's Prometheus collectors. Label cardinality is
// deliberately bounded: no IPs, user ids, asset ids or paths (spec §48).
type Metrics struct {
	registry *prometheus.Registry

	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPDurationSeconds *prometheus.HistogramVec
	DBQueryDuration     *prometheus.HistogramVec

	ScannerTasksTotal   *prometheus.CounterVec
	ScannerTaskDuration *prometheus.HistogramVec
	ScannerTargetsTotal prometheus.Counter
	ScannerPortsTotal   prometheus.Counter

	FingerprintsTotal       *prometheus.CounterVec
	VulnMatchesTotal        *prometheus.CounterVec
	FeedSyncTotal           *prometheus.CounterVec
	FeedSyncDurationSeconds *prometheus.HistogramVec

	EventsIngestedTotal   *prometheus.CounterVec
	EventsDroppedTotal    *prometheus.CounterVec
	DetectionMatchesTotal *prometheus.CounterVec

	AgentConnected          prometheus.Gauge
	AgentLastSeenSeconds    *prometheus.GaugeVec
	NATSConsumerLag         *prometheus.GaugeVec
	ClickhouseInsertLatency *prometheus.HistogramVec
}

// New builds and registers the default metric set.
func New(namespace string) *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(
		prometheus.ProcessCollectorOpts{Namespace: namespace}))
	m := &Metrics{registry: reg}
	m.HTTPRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "http_requests_total",
		Help: "HTTP requests processed."},
		[]string{"service", "method", "route", "status"})
	m.HTTPDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "http_request_duration_seconds",
		Help: "HTTP request latency.", Buckets: prometheus.DefBuckets},
		[]string{"service", "method", "route"})
	m.DBQueryDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "db_query_duration_seconds",
		Help: "Database query latency.", Buckets: prometheus.ExponentialBuckets(0.001, 4, 8)},
		[]string{"service", "op"})
	m.ScannerTasksTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "scanner_tasks_total",
		Help: "Scan tasks by state."}, []string{"service", "type", "state"})
	m.ScannerTaskDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "scanner_task_duration_seconds",
		Help: "Scan task duration.", Buckets: prometheus.ExponentialBuckets(0.1, 3, 8)},
		[]string{"service", "type"})
	m.ScannerTargetsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Name: "scanner_targets_total", Help: "Targets scanned."})
	m.ScannerPortsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Name: "scanner_ports_total", Help: "Ports probed."})
	m.FingerprintsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "fingerprints_total",
		Help: "Fingerprints performed."}, []string{"service", "kind"})
	m.VulnMatchesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "vulnerability_matches_total",
		Help: "Vulnerability matches by type."}, []string{"service", "match_type"})
	m.FeedSyncTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "feed_sync_total",
		Help: "Feed sync attempts."}, []string{"service", "feed", "status"})
	m.FeedSyncDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "feed_sync_duration_seconds",
		Help: "Feed sync duration.", Buckets: prometheus.ExponentialBuckets(1, 2, 10)},
		[]string{"service", "feed"})
	m.EventsIngestedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "events_ingested_total",
		Help: "Events ingested."}, []string{"service", "source"})
	m.EventsDroppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "events_dropped_total",
		Help: "Events dropped (validation/limits)."}, []string{"service", "reason"})
	m.DetectionMatchesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "detection_matches_total",
		Help: "Detection matches."}, []string{"service", "rule_type"})
	m.AgentConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace, Name: "agent_connected", Help: "Agents currently connected."})
	m.AgentLastSeenSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "agent_last_seen_seconds",
		Help: "Seconds since agent last seen."}, []string{"site"})
	m.NATSConsumerLag = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "nats_consumer_lag",
		Help: "JetStream consumer pending messages."}, []string{"consumer"})
	m.ClickhouseInsertLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "clickhouse_insert_latency_seconds",
		Help: "ClickHouse batch insert latency.", Buckets: prometheus.ExponentialBuckets(0.01, 3, 6)},
		[]string{"service", "table"})

	reg.MustRegister(
		m.HTTPRequestsTotal, m.HTTPDurationSeconds, m.DBQueryDuration,
		m.ScannerTasksTotal, m.ScannerTaskDuration, m.ScannerTargetsTotal, m.ScannerPortsTotal,
		m.FingerprintsTotal, m.VulnMatchesTotal, m.FeedSyncTotal, m.FeedSyncDurationSeconds,
		m.EventsIngestedTotal, m.EventsDroppedTotal, m.DetectionMatchesTotal,
		m.AgentConnected, m.AgentLastSeenSeconds, m.NATSConsumerLag, m.ClickhouseInsertLatency,
	)
	return m
}

// Handler returns the /metrics HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Registry exposes the underlying registry (tests, custom collectors).
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }
