// Counter Reset Sidecar - Multi-sink
// ==================================
//
// This Go sidecar scrapes one or more Prometheus endpoints for selected **counter**
// metrics, tracks resets (value drops vs previous sample), and republishes the
// values with three added labels:
//   - destination: the scraped target address (e.g., "10.0.0.1:9100")
//   - job: static job label attached to emitted metrics (default: "sidecar_metrics")
//   - reset_id: an incrementing ID that changes on each reset to create a new series
//
// Outputs (any combination, chosen via flags; multiple sinks can be active at once):
//   1) expose        -> sidecar exposes /metrics; Prometheus scrapes it
//   2) pushgateway   -> sidecar pushes to a Pushgateway
//   3) remote_write  -> sidecar pushes via Prometheus remote_write (supports TLS + optional CA file)
//   4) file          -> sidecar writes JSON lines to a file
//                      Each line looks like:
//                        {"metric":"http_requests_total","labels":{"destination":"10.0.0.1:9100","job":"sidecar_metrics","type":"blah","reset_id":"0"},"value":76205,"time":"2025-08-30T11:00:00.123456789+02:00"}
//
// Notes:
//   - You can enable any subset of sinks; omitted flags disable that sink.
//   - Each sink is isolated: if one fails, others continue.
//   - Timezone can be controlled with --timezone (IANA TZ database name, default: Local).
//   - Verbose logging can be enabled with --verbose.
//   - Basic authentication for scrape targets can be enabled with --basic-auth-user and --basic-auth-pass (applies to all targets).
//   - For expose and push sinks, only the current series segment and the immediately previous one (if any) are emitted, based on reset_id.
//   - Remote write can use TLS if the URL is https:// ; optionally provide a CA file with --remote-write-ca-file.
//   - Scrape targets can use TLS or mTLS if you provide --tls_targets_ca and optionally --tls_cert/--tls_key (applies to all HTTPS targets).
//
// Flags:
//   --targets                 comma-separated list of host:port or full URLs (same path)
//   --metrics                 comma-separated metric names to track (counters)
//   --metrics-path            path to scrape on each target (default: /metrics)
//   --passthrough-labels      comma-separated label keys to preserve from scraped samples
//   --listen-addr             address to bind when exposing (enables expose sink if set)
//   --pushgateway-url         pushgateway base URL (enables Pushgateway sink)
//   --push-job                pushgateway job name (default: reset_sidecar)
//   --output-file             file path for JSONL snapshots (enables File sink)
//   --remote-write-url        Prometheus remote_write URL (enables RemoteWrite sink)
//   --remote-write-user       basic auth username for remote-write-url (optional)
//   --remote-write-pass       basic auth password for remote-write-url (optional)
//   --remote-write-ca-file    CA file path for TLS verification when using remote_write over HTTPS (optional)
//   --remote-write-insecure-skip-verify  true
//   --basic-auth-user         basic auth username for scrape targets
//   --basic-auth-pass         basic auth password for scrape targets
//   --tls_targets_ca          CA file path for TLS verification when scraping HTTPS targets (optional)
//   --tls_cert                client TLS certificate for scraping HTTPS targets (optional, for mTLS)
//   --tls_key                 client TLS key for scraping HTTPS targets (optional, for mTLS)
//   --scrape-interval         e.g., 30s (default)
//   --publish-interval        e.g., 15m (default)
//   --timezone                IANA timezone for file timestamps (default: Local)
//   --job                     job label to attach to emitted metrics (default: sidecar_metrics)
//   --verbose                 enable verbose logging
//   --log-file               path to log file (optional; default logs to stderr/stdout)
//
// Schedules:
//   - Scrape interval:       default 30s
//   - Publish (to all active sinks): default 15m
//   - A reset triggers an immediate publish (flush) to all active sinks
//
// Example exported series shape (for expose/push/remote_write):
//   http_requests_total{destination="10.0.0.1:9100", job="sidecar_metrics", type="blah_blah", reset_id="0"} 76205
//
// Example JSONL log line (for file sink):
//   {"metric":"http_requests_total","labels":{"destination":"10.0.0.1:9100","job":"sidecar_metrics","type":"blah_blah","reset_id":"0"},"value":76205,"time":"2025-08-30T13:00:00.000000000+02:00"}
//
// Build & Run (examples):
//
//   # Expose only
//   ./reset-sidecar \
//     --targets=10.0.0.1:9100 \
//     --metrics=http_requests_total \
//     --passthrough-labels=type \
//     --listen-addr=":9110" \
//     --job=sidecar_metrics
//
//   # Pushgateway + File
//   ./reset-sidecar \
//     --targets=10.0.0.1:9100 \
//     --metrics=http_requests_total \
//     --passthrough-labels=type \
//     --pushgateway-url=http://pushgateway:9091 \
//     --push-job=reset_sidecar \
//     --output-file=/var/log/reset_sidecar.jsonl \
//     --job=sidecar_metrics
//
//   # All sinks at once with TLS remote_write + basic auth and timezone
//   ./reset-sidecar \
//     --targets=10.0.0.1:9100 \
//     --metrics=http_requests_total \
//     --passthrough-labels=type,method \
//     --listen-addr=":9110" \
//     --pushgateway-url=http://pushgateway:9091 \
//     --output-file=/var/log/reset_sidecar.jsonl \
//     --remote-write-url=https://prom:9090/api/v1/write \
//     --remote-write-user=rw_user \
//     --remote-write-pass=rw_pass \
//     --remote-write-ca-file=/etc/prometheus/root-ca.pem \
//     --timezone=Europe/Paris \
//     --job=sidecar_metrics \
//     --verbose
//
//   # (Reproduced from your usage, adjusted to include --job)
//   ./reset-sidecar-four \
//     --targets="192.168.1.2:3031" \
//     --metrics="log_metric_counter_a_b_ab" \
//     --passthrough-labels="type" \
//     --listen-addr=":9110" \
//     --output-file="reset_sidecar.jsonl" \
//     --timezone="Asia/Tehran" \
//     --publish-interval="2m" \
//     --scrape-interval="20s" \
//     --job="sidecar_metrics"
//
// Notes:
// - If you pass raw host:port as targets, the sidecar assumes "http://" + host:port + metrics-path
// - If you pass full URLs (http/https), the sidecar uses them as-is (ignores metrics-path)
// - If a sink flag is not provided (e.g., --remote-write-url), it is silently skipped
// - Error handling is per-sink: one failing sink does NOT block others
// - On reset, historical series segments are preserved in memory, but only the current and immediately previous segments are emitted in the expose and push sinks (e.g., reset_id=5 and reset_id=4). File and remote_write sinks only publish the current segment.


package main


import (
    "bufio"
    "bytes"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "os"
    "sort"
    "strings"
    "sync"
    "time"


    "github.com/golang/protobuf/proto"
    "github.com/golang/snappy"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/prometheus/client_golang/prometheus/push"
    "github.com/prometheus/common/expfmt"
    dto "github.com/prometheus/client_model/go"
    "github.com/prometheus/prometheus/prompb"
)


// --------------------
// Configuration flags
// --------------------
var (
    flagTargets             = flag.String("targets", "", "Comma-separated list of target hosts or URLs")
    flagMetrics             = flag.String("metrics", "", "Comma-separated COUNTER metric names to track")
    flagMetricsPath         = flag.String("metrics-path", "/metrics", "Metrics path if targets are host:port")
    flagPassthroughLabels   = flag.String("passthrough-labels", "", "Comma-separated label keys to preserve")
    flagListenAddr          = flag.String("listen-addr", "", "Listen addr for expose sink (enables if set)")
    flagPushGatewayURL      = flag.String("pushgateway-url", "", "Pushgateway URL for push sink (enables if set)")
    flagPushJob             = flag.String("push-job", "reset_sidecar", "Pushgateway job name")
    flagOutputFile          = flag.String("output-file", "", "Path to JSONL file (enables file sink if set)")
    flagRemoteWriteURL      = flag.String("remote-write-url", "", "Remote write endpoint URL (enables remote_write sink if set)")
    flagRemoteWriteUser     = flag.String("remote-write-user", "", "Basic auth username for remote-write-url (optional)")
    flagRemoteWritePass     = flag.String("remote-write-pass", "", "Basic auth password for remote-write-url (optional)")
    flagRemoteWriteCAFile   = flag.String("remote-write-ca-file", "", "CA file path for TLS verification (optional)")
    flagBasicUser           = flag.String("basic-auth-user", "", "Basic auth username for scrape targets")
    flagBasicPass           = flag.String("basic-auth-pass", "", "Basic auth password for scrape targets")
    flagTLSTargetsCA        = flag.String("tls_targets_ca", "", "CA file path for TLS verification when scraping HTTPS targets (optional)")
    flagTLSCert             = flag.String("tls_cert", "", "Client TLS certificate file for scraping HTTPS targets (optional, for mTLS)")
    flagTLSKey              = flag.String("tls_key", "", "Client TLS key file for scraping HTTPS targets (optional, for mTLS)")
    flagScrapeInterval      = flag.Duration("scrape-interval", 30*time.Second, "Scrape interval")
    flagPublishInterval     = flag.Duration("publish-interval", 15*time.Minute, "Publish interval")
    flagTimezone            = flag.String("timezone", "Local", "Timezone for file sink timestamps")
    flagJob                 = flag.String("job", "sidecar_metrics", "Job label to attach to emitted metrics")
    flagVerbose             = flag.Bool("verbose", false, "Enable verbose logging")
    flagRemoteWriteTimeout  = flag.Duration("remote-write-timeout", 15*time.Second, "HTTP timeout for remote_write")
    flagScrapeHTTPTimeout   = flag.Duration("scrape-http-timeout", 10*time.Second, "HTTP timeout for scraping targets")
    flagInsecureSkipVerify  = flag.Bool("remote-write-insecure-skip-verify", false, "Skip TLS verification for remote_write (NOT recommended)")
    flagRemoteWriteSniName  = flag.String("remote-write-server-name", "", "Override TLS SNI/ServerName for remote_write (optional)")
	flagLogFile            = flag.String("log-file", "", "Path to log file (optional; defaults to stderr/stdout)")
)


// --------------------
// Types & State
// --------------------


type labelOrder struct {
    passthrough []string
}


type seriesKey struct {
    metricName  string
    destination string
    valuesKey   string
}


type seriesState struct {
    current        float64
    last           float64
    published      float64
    lastUpdateTime time.Time
    resetID        int
    initialized    bool
}


type stateStore struct {
    mu      sync.RWMutex
    labels  labelOrder
    states  map[seriesKey][]*seriesState
    metrics []string
}


// --------------------
// Logging helper
// --------------------
func logf(format string, args ...any) {
    if *flagVerbose {
        log.Printf(format, args...)
    }
}


// --------------------
// Collector for expose/push
// --------------------
type snapshotCollector struct {
    store      *stateStore
    descByName map[string]*prometheus.Desc
    labelNames []string
}


func newSnapshotCollector(store *stateStore) *snapshotCollector {
    // Label order: destination, job, <passthrough...>, reset_id
    ln := make([]string, 0, 3+len(store.labels.passthrough))
    ln = append(ln, "destination")
    ln = append(ln, "job")
    ln = append(ln, store.labels.passthrough...)
    ln = append(ln, "reset_id")


    descs := make(map[string]*prometheus.Desc)
    for _, m := range store.metrics {
        descs[m] = prometheus.NewDesc(m,
            "republished counter snapshot with destination, job and reset_id",
            ln, nil)
    }
    return &snapshotCollector{store: store, descByName: descs, labelNames: ln}
}


func (c *snapshotCollector) Describe(ch chan<- *prometheus.Desc) {
    for _, d := range c.descByName {
        ch <- d
    }
}


func (c *snapshotCollector) Collect(ch chan<- prometheus.Metric) {
    c.store.mu.RLock()
    defer c.store.mu.RUnlock()
    for key, segments := range c.store.states {
        // Emit only the last two segments (current and immediately previous, if it exists)
        start := 0
        if len(segments) > 2 {
            start = len(segments) - 2
        }
        for _, st := range segments[start:] {
            desc := c.descByName[key.metricName]
            if desc == nil {
                continue
            }
            labels := make([]string, 0, len(c.labelNames))
            labels = append(labels, key.destination)
            labels = append(labels, *flagJob)
            if key.valuesKey != "" && len(c.store.labels.passthrough) > 0 {
                labels = append(labels, strings.Split(key.valuesKey, "|")...)
            }
            labels = append(labels, fmt.Sprintf("%d", st.resetID))
            ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, st.published, labels...)
        }
    }
}


// --------------------
// Scraping & Parsing
// --------------------


func isFullURL(s string) bool {
    u, err := url.Parse(s)
    return err == nil && u.Scheme != "" && u.Host != ""
}


func buildScrapeURL(target, path string) (string, error) {
    if isFullURL(target) {
        return target, nil
    }
    if !strings.Contains(target, ":") {
        return "", fmt.Errorf("bad target %q (need host:port)", target)
    }
    return fmt.Sprintf("http://%s%s", target, path), nil
}


func scrapeOnce(client *http.Client, store *stateStore, targets []string, metrics []string, path string, labelKeys []string, onPublish func()) {
    want := make(map[string]struct{}, len(metrics))
    for _, m := range metrics {
        m = strings.TrimSpace(m)
        if m != "" {
            want[m] = struct{}{}
        }
    }


    resets := make(map[seriesKey]float64)
    now := time.Now()


    for _, t := range targets {
        scrapeURL, err := buildScrapeURL(t, path)
        if err != nil {
            log.Printf("[warn] bad target %q: %v", t, err)
            continue
        }
        req, err := http.NewRequest("GET", scrapeURL, nil)
        if err != nil {
            log.Printf("[warn] request creation for %s failed: %v", scrapeURL, err)
            continue
        }
        if *flagBasicUser != "" && *flagBasicPass != "" {
            req.SetBasicAuth(*flagBasicUser, *flagBasicPass)
        }
        resp, err := client.Do(req)
        if err != nil {
            log.Printf("[warn] scrape %s failed: %v", scrapeURL, err)
            continue
        }
        if resp.StatusCode != http.StatusOK {
            log.Printf("[warn] scrape %s bad status: %s", scrapeURL, resp.Status)
            resp.Body.Close()
            continue
        }
        parser := expfmt.TextParser{}
        parsed, err := parser.TextToMetricFamilies(bufio.NewReader(resp.Body))
        resp.Body.Close()
        if err != nil {
            log.Printf("[warn] parse %s failed: %v", scrapeURL, err)
            continue
        }
        for name, fam := range parsed {
            if _, ok := want[name]; !ok {
                continue
            }
            if fam.GetType() != dto.MetricType_COUNTER {
                continue
            }
            for _, m := range fam.Metric {
                val := m.GetCounter().GetValue()
                labelMap := make(map[string]string, len(m.Label))
                for _, lp := range m.Label {
                    labelMap[lp.GetName()] = lp.GetValue()
                }
                values := make([]string, len(labelKeys))
                for i, lk := range labelKeys {
                    values[i] = labelMap[lk]
                }
                key := seriesKey{name, t, strings.Join(values, "|")}
                store.mu.Lock()
                segments, ok := store.states[key]
                if !ok {
                    newSt := &seriesState{
                        current:        val,
                        last:           val,
                        published:      val,
                        lastUpdateTime: now,
                        initialized:    true,
                    }
                    store.states[key] = []*seriesState{newSt}
                    store.mu.Unlock()
                    continue
                }
                st := segments[len(segments)-1]
                if !st.initialized {
                    st.last = val
                    st.current = val
                    st.published = val
                    st.lastUpdateTime = now
                    st.initialized = true
                    store.mu.Unlock()
                    continue
                }
                if val < st.last {
                    resets[key] = val
                } else {
                    st.current = val
                    st.last = val
                    st.lastUpdateTime = now
                }
                store.mu.Unlock()
            }
        }
    }


    if len(resets) > 0 {
        // Publish the pre-reset values first
        publishSnapshot(store)
        onPublish()
        store.mu.Lock()
        for key, newVal := range resets {
            segments := store.states[key]
            oldSt := segments[len(segments)-1]
            newResetID := oldSt.resetID + 1
            newSt := &seriesState{
                current:        newVal,
                last:           newVal,
                published:      newVal,
                lastUpdateTime: now,
                resetID:        newResetID,
                initialized:    true,
            }
            // Keep only the last two segments
            if len(segments) >= 2 {
                segments = segments[len(segments)-1:]
            }
            store.states[key] = append(segments, newSt)
            logf("reset detected for %s on %s, reset_id=%d", key.metricName, key.destination, newResetID)
        }
        store.mu.Unlock()
        // Publish the new reset values
        publishSnapshot(store)
        onPublish()
    }
}


func publishSnapshot(store *stateStore) {
    store.mu.Lock()
    defer store.mu.Unlock()
    for _, segments := range store.states {
        if len(segments) > 0 {
            seg := segments[len(segments)-1]
            seg.published = seg.current
        }
    }
}


// --------------------
// Output Helpers
// --------------------


func doPush(pgURL, job string, reg *prometheus.Registry) {
    if err := push.New(pgURL, job).Gatherer(reg).Push(); err != nil {
        log.Printf("[warn] push failed: %v", err)
    } else {
        logf("[info] pushed to %s job=%s", pgURL, job)
    }
}


func doFileWrite(store *stateStore, passthrough []string, outFile string) {
    f, err := os.OpenFile(outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Printf("[warn] file open failed: %v", err)
        return
    }
    defer f.Close()
    enc := json.NewEncoder(f)


    loc := time.Local
    if *flagTimezone != "Local" {
        var lerr error
        loc, lerr = time.LoadLocation(*flagTimezone)
        if lerr != nil {
            log.Printf("[warn] invalid timezone %s: %v", *flagTimezone, lerr)
        }
    }


    store.mu.RLock()
    defer store.mu.RUnlock()
    for key, segments := range store.states {
        if len(segments) == 0 {
            continue
        }
        st := segments[len(segments)-1]
        labels := map[string]string{
            "destination": key.destination,
            "job":         *flagJob,
            "reset_id":    fmt.Sprintf("%d", st.resetID),
        }
        if key.valuesKey != "" && len(passthrough) > 0 {
            vals := strings.Split(key.valuesKey, "|")
            for i, lk := range passthrough {
                if i < len(vals) {
                    labels[lk] = vals[i]
                }
            }
        }
        obj := map[string]any{
            "metric": key.metricName,
            "labels": labels,
            "value":  st.published,
            "time":   st.lastUpdateTime.In(loc).Format(time.RFC3339Nano),
        }
        if err := enc.Encode(obj); err != nil {
            log.Printf("[warn] json encode failed: %v", err)
            return
        }
    }
    logf("wrote snapshot to %s", outFile)
}


func buildRemoteWriteHTTPClient() *http.Client {
    // Transport with optional TLS config
    tr := &http.Transport{}


    // TLS configuration when CA file is provided, or when flags request special behavior
    if *flagRemoteWriteCAFile != "" || *flagInsecureSkipVerify || *flagRemoteWriteSniName != "" {
        tlsCfg := &tls.Config{
            InsecureSkipVerify: *flagInsecureSkipVerify, // #nosec G402 - controlled by flag
        }
        if *flagRemoteWriteSniName != "" {
            tlsCfg.ServerName = *flagRemoteWriteSniName
        }
        if *flagRemoteWriteCAFile != "" {
            caPEM, err := os.ReadFile(*flagRemoteWriteCAFile)
            if err != nil {
                log.Printf("[warn] remote_write CA file read failed: %v", err)
            } else {
                pool := x509.NewCertPool()
                if ok := pool.AppendCertsFromPEM(caPEM); !ok {
                    log.Printf("[warn] remote_write CA file %s: no certs appended", *flagRemoteWriteCAFile)
                } else {
                    tlsCfg.RootCAs = pool
                }
            }
        }
        tr.TLSClientConfig = tlsCfg
    }


    return &http.Client{
        Transport: tr,
        Timeout:   *flagRemoteWriteTimeout,
    }
}


// Build HTTP client used for scraping targets (supports TLS and mTLS).
func buildScrapeHTTPClient() *http.Client {
    tr := &http.Transport{}

    if *flagTLSTargetsCA != "" || (*flagTLSCert != "" && *flagTLSKey != "") {
        tlsCfg := &tls.Config{}

        // Optional CA bundle for HTTPS scrape targets
        if *flagTLSTargetsCA != "" {
            caPEM, err := os.ReadFile(*flagTLSTargetsCA)
            if err != nil {
                log.Printf("[warn] scrape CA file read failed: %v", err)
            } else {
                pool := x509.NewCertPool()
                if ok := pool.AppendCertsFromPEM(caPEM); !ok {
                    log.Printf("[warn] scrape CA file %s: no certs appended", *flagTLSTargetsCA)
                } else {
                    tlsCfg.RootCAs = pool
                }
            }
        }

        // Optional client certificate for mTLS with scrape targets
        if *flagTLSCert != "" && *flagTLSKey != "" {
            cert, err := tls.LoadX509KeyPair(*flagTLSCert, *flagTLSKey)
            if err != nil {
                log.Printf("[warn] scrape client TLS cert/key load failed: %v", err)
            } else {
                tlsCfg.Certificates = []tls.Certificate{cert}
            }
        }

        tr.TLSClientConfig = tlsCfg
    }

    return &http.Client{
        Transport: tr,
        Timeout:   *flagScrapeHTTPTimeout,
    }
}


func doRemoteWrite(store *stateStore, passthrough []string, remoteURL string) {
    store.mu.RLock()
    defer store.mu.RUnlock()


    var series []prompb.TimeSeries


    for key, segments := range store.states {
        if len(segments) == 0 {
            continue
        }
        st := segments[len(segments)-1]
        lbls := []prompb.Label{
            {Name: "__name__", Value: key.metricName},
            {Name: "destination", Value: key.destination},
            {Name: "job", Value: *flagJob},
            {Name: "reset_id", Value: fmt.Sprintf("%d", st.resetID)},
        }
        if key.valuesKey != "" && len(passthrough) > 0 {
            vals := strings.Split(key.valuesKey, "|")
            for i, lk := range passthrough {
                if i < len(vals) {
                    lbls = append(lbls, prompb.Label{Name: lk, Value: vals[i]})
                }
            }
        }
        series = append(series, prompb.TimeSeries{
            Labels: lbls,
            Samples: []prompb.Sample{{
                Value:     st.published,
                Timestamp: st.lastUpdateTime.UnixMilli(),
            }},
        })
    }


    req := &prompb.WriteRequest{Timeseries: series}
    data, err := proto.Marshal(req)
    if err != nil {
        log.Printf("[warn] remote_write marshal failed: %v", err)
        return
    }
    snappyData := snappy.Encode(nil, data)
    httpReq, err := http.NewRequest("POST", remoteURL, bytes.NewReader(snappyData))
    if err != nil {
        log.Printf("[warn] remote_write req failed: %v", err)
        return
    }
    httpReq.Header.Set("Content-Encoding", "snappy")
    httpReq.Header.Set("Content-Type", "application/x-protobuf")
    httpReq.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")


    // Optional basic auth for remote_write
    if *flagRemoteWriteUser != "" && *flagRemoteWritePass != "" {
        httpReq.SetBasicAuth(*flagRemoteWriteUser, *flagRemoteWritePass)
    }


    client := buildRemoteWriteHTTPClient()
    resp, err := client.Do(httpReq)
    if err != nil {
        log.Printf("[warn] remote_write failed: %v", err)
        return
    }
    io.Copy(io.Discard, resp.Body)
    resp.Body.Close()
    if resp.StatusCode >= 400 {
        log.Printf("[warn] remote_write %s bad status: %s", remoteURL, resp.Status)
    } else {
        logf("remote_write %s status=%s", remoteURL, resp.Status)
    }
}


// --------------------
// Main
// --------------------


func main() {
    flag.Parse()

	// Optional log file: if set, log to both stderr and the given file.
	if *flagLogFile != "" {
		f, err := os.OpenFile(*flagLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("failed to open log file %s: %v", *flagLogFile, err)
		}
		// Send logs to both stderr (container logs) and file.
		mw := io.MultiWriter(os.Stderr, f)
		log.SetOutput(mw)
	}

    targets := splitCSV(*flagTargets)
    metrics := splitCSV(*flagMetrics)
    passthrough := splitCSV(*flagPassthroughLabels)


    if len(targets) == 0 || len(metrics) == 0 {
        log.Fatalf("--targets and --metrics are required")
    }


    targets = normalizeList(targets)
    metrics = normalizeList(metrics)


    store := &stateStore{
        labels:  labelOrder{passthrough: passthrough},
        states:  make(map[seriesKey][]*seriesState),
        metrics: metrics,
    }
    collector := newSnapshotCollector(store)
    reg := prometheus.NewRegistry()
    reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
    reg.MustRegister(prometheus.NewGoCollector())
    reg.MustRegister(collector)


    // Scrape HTTP client now supports TLS and mTLS via --tls_targets_ca/--tls_cert/--tls_key
    client := buildScrapeHTTPClient()
    scrapeTicker := time.NewTicker(*flagScrapeInterval)
    publishTicker := time.NewTicker(*flagPublishInterval)
    defer scrapeTicker.Stop()
    defer publishTicker.Stop()


    publishSinks := func() {
        if *flagPushGatewayURL != "" {
            doPush(*flagPushGatewayURL, *flagPushJob, reg)
        }
        if *flagOutputFile != "" {
            doFileWrite(store, passthrough, *flagOutputFile)
        }
        if *flagRemoteWriteURL != "" {
            doRemoteWrite(store, passthrough, *flagRemoteWriteURL)
        }
    }


    // Expose sink setup
    if *flagListenAddr != "" {
        http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{EnableOpenMetrics: true}))
        go func() {
            logf("[info] exposing /metrics on %s", *flagListenAddr)
            if err := http.ListenAndServe(*flagListenAddr, nil); err != nil {
                log.Fatalf("listen failed: %v", err)
            }
        }()
    }


    // Initial scrape & publish
    scrapeOnce(client, store, targets, metrics, *flagMetricsPath, passthrough, publishSinks)
    publishSnapshot(store)
    publishSinks()


    for {
        select {
        case <-scrapeTicker.C:
            scrapeOnce(client, store, targets, metrics, *flagMetricsPath, passthrough, publishSinks)
        case <-publishTicker.C:
            publishSnapshot(store)
            publishSinks()
        }
    }
}


// --------------------
// Utils
// --------------------
func splitCSV(s string) []string {
    if strings.TrimSpace(s) == "" {
        return nil
    }
    parts := strings.Split(s, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        if p = strings.TrimSpace(p); p != "" {
            out = append(out, p)
        }
    }
    return out
}


func normalizeList(xs []string) []string {
    m := map[string]struct{}{}
    for _, x := range xs {
        m[x] = struct{}{}
    }
    res := make([]string, 0, len(m))
    for x := range m {
        res = append(res, x)
    }
    sort.Strings(res)
    return res
}
