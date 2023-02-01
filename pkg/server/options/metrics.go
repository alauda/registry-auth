package options

import (
	"bufio"
	"github.com/alauda/registry-auth/pkg/server"
	"github.com/emicklei/go-restful"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	flagEnableMetrics = "metrics"
)

const (
	configEnableMetrics = "monitoring.metrics"
)

// MetricsOptions holds the Debugging options.
type MetricsOptions struct {
	EnableMetrics bool
}

// NewMetricsOptions creates the default MetricsOptions object.
func NewMetricsOptions() *MetricsOptions {
	return &MetricsOptions{
		EnableMetrics: true,
	}
}

// AddFlags adds flags related to debugging for controller manager to the specified FlagSet.
func (o *MetricsOptions) AddFlags(fs *pflag.FlagSet) {
	if o == nil {
		return
	}

	fs.Bool(flagEnableMetrics, o.EnableMetrics,
		"Enable metrics for prometheus web interface host:port/metrics")
	_ = viper.BindPFlag(configEnableMetrics, fs.Lookup(flagEnableMetrics))
}

// ApplyFlags parsing parameters from the command line or configuration file
// to the options instance.
func (o *MetricsOptions) ApplyFlags() []error {
	var errs []error

	o.EnableMetrics = viper.GetBool(configEnableMetrics)

	return errs
}

// ApplyToServer apply options to server
func (o *MetricsOptions) ApplyToServer(server *server.Server) (err error) {
	if o == nil || !o.EnableMetrics {
		return
	}
	for _, metric := range metrics {
		prometheus.MustRegister(metric)
	}

	server.Container().Handle("/metrics/", http.HandlerFunc(redirectTo("/metrics")))

	// change prometheus.Handler() to promhttp.Handler() to skipper default metrics registration
	server.Container().Handle("/metrics", promhttp.Handler())
	server.Container().Filter(o.Filter)
	return
}

// Filter middleware for metrics
func (o *MetricsOptions) Filter(req *restful.Request, res *restful.Response, chain *restful.FilterChain) {
	start := time.Now()
	delegate := &ResponseWriterDelegator{ResponseWriter: res.ResponseWriter}

	_, cn := res.ResponseWriter.(http.CloseNotifier)
	_, fl := res.ResponseWriter.(http.Flusher)
	_, hj := res.ResponseWriter.(http.Hijacker)
	_, rf := res.ResponseWriter.(io.ReaderFrom)
	var rw http.ResponseWriter
	if cn && fl && hj && rf {
		rw = &fancyResponseWriterDelegator{delegate}
	} else {
		rw = delegate
	}
	res.ResponseWriter = rw
	size := calculateRequestSize(req.Request)

	chain.ProcessFilter(req, res)

	elapsed := time.Now().Sub(start)
	elapsedMicroseconds := float64(elapsed / time.Microsecond)
	userAgent := cleanUserAgent(req.Request.UserAgent())
	code := codeToString(res.StatusCode())
	path := req.SelectedRoutePath()

	// request count
	requestCounter.WithLabelValues(req.Request.Method, path, userAgent, code).Inc()
	// request latency
	requestDuration.WithLabelValues(req.Request.Method, path, userAgent, code).Observe(elapsedMicroseconds)
	// request size
	requestSize.WithLabelValues(req.Request.Method, path, userAgent, code).Observe(size)
	// response size
	responseSize.WithLabelValues(req.Request.Method, path, userAgent, code).Observe(float64(delegate.ContentLength()))
}

// resettableCollector is the interface implemented by prometheus.MetricVec
// that can be used by Prometheus to collect metrics and reset their values.
type resettableCollector interface {
	prometheus.Collector
	Reset()
}

var (
	// from k8s.io/apiserver/pkg/endpoints/metrics/metrics.go
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Counter of apiserver requests broken out for each verb, API resource, client, and HTTP response contentType and code.",
		},
		[]string{"method", "path", "client", "code"},
	)
	requestDuration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "http_request_duration_seconds",
			Help:       "The HTTP request latencies in seconds",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method", "path", "client", "code"},
	)
	requestSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "http_request_size_bytes",
			Help:       "The HTTP request sizes in bytes",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method", "path", "client", "code"},
	)
	responseSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "http_response_size_bytes",
			Help:       "The HTTP response sizes in bytes",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method", "path", "client", "code"},
	)
	kubectlExeRegexp = regexp.MustCompile(`^.*((?i:kubectl\.exe))`)

	metrics = []resettableCollector{
		requestCounter,
		requestDuration,
		requestSize,
		responseSize,
	}
)

// from k8s.io/apiserver/pkg/endpoints/metrics/metrics.go
func cleanUserAgent(ua string) string {
	// We collapse all "web browser"-type user agents into one "browser" to reduce metric cardinality.
	if strings.HasPrefix(ua, "Mozilla/") {
		return "Browser"
	}
	// If an old "kubectl.exe" has passed us its full path, we discard the path portion.
	ua = kubectlExeRegexp.ReplaceAllString(ua, "$1")
	return ua
}

// Small optimization over Itoa
// from k8s.io/apiserver/pkg/endpoints/metrics/metrics.go
func codeToString(s int) string {
	switch s {
	case 100:
		return "100"
	case 101:
		return "101"

	case 200:
		return "200"
	case 201:
		return "201"
	case 202:
		return "202"
	case 203:
		return "203"
	case 204:
		return "204"
	case 205:
		return "205"
	case 206:
		return "206"

	case 300:
		return "300"
	case 301:
		return "301"
	case 302:
		return "302"
	case 304:
		return "304"
	case 305:
		return "305"
	case 307:
		return "307"

	case 400:
		return "400"
	case 401:
		return "401"
	case 402:
		return "402"
	case 403:
		return "403"
	case 404:
		return "404"
	case 405:
		return "405"
	case 406:
		return "406"
	case 407:
		return "407"
	case 408:
		return "408"
	case 409:
		return "409"
	case 410:
		return "410"
	case 411:
		return "411"
	case 412:
		return "412"
	case 413:
		return "413"
	case 414:
		return "414"
	case 415:
		return "415"
	case 416:
		return "416"
	case 417:
		return "417"
	case 418:
		return "418"

	case 500:
		return "500"
	case 501:
		return "501"
	case 502:
		return "502"
	case 503:
		return "503"
	case 504:
		return "504"
	case 505:
		return "505"

	case 428:
		return "428"
	case 429:
		return "429"
	case 431:
		return "431"
	case 511:
		return "511"

	default:
		return strconv.Itoa(s)
	}
}

// Calculate request size
func calculateRequestSize(r *http.Request) float64 {
	s := 0

	if r.URL != nil {
		s += len(r.URL.String())
	}
	s += len(r.Method)
	s += len(r.Proto)
	for name, values := range r.Header {
		s += len(name)
		for _, value := range values {
			s += len(value)
		}
	}
	s += len(r.Host)

	// N.B. r.Form and r.MultipartForm are assumed to be included in r.URL.

	if r.ContentLength != -1 {
		s += int(r.ContentLength)
	}
	return float64(s)
}

// from k8s.io/apiserver/pkg/endpoints/metrics/metrics.go

// ResponseWriterDelegator interface wraps http.ResponseWriter to additionally record content-length, status-code, etc.
type ResponseWriterDelegator struct {
	http.ResponseWriter

	status      int
	written     int64
	wroteHeader bool
}

// WriteHeader overwrites http.ResponseWriter method
func (r *ResponseWriterDelegator) WriteHeader(code int) {
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

// Write overwrites io.Writer method
func (r *ResponseWriterDelegator) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.written += int64(n)
	return n, err
}

// Status returns status
func (r *ResponseWriterDelegator) Status() int {
	return r.status
}

// ContentLength returns content length
func (r *ResponseWriterDelegator) ContentLength() int {
	return int(r.written)
}

type fancyResponseWriterDelegator struct {
	*ResponseWriterDelegator
}

func (f *fancyResponseWriterDelegator) CloseNotify() <-chan bool {
	return f.ResponseWriter.(http.CloseNotifier).CloseNotify()
}

func (f *fancyResponseWriterDelegator) Flush() {
	f.ResponseWriter.(http.Flusher).Flush()
}

func (f *fancyResponseWriterDelegator) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return f.ResponseWriter.(http.Hijacker).Hijack()
}

func (f *fancyResponseWriterDelegator) ReadFrom(r io.Reader) (int64, error) {
	if !f.wroteHeader {
		f.WriteHeader(http.StatusOK)
	}
	n, err := f.ResponseWriter.(io.ReaderFrom).ReadFrom(r)
	f.written += n
	return n, err
}

// redirectTo redirects request to a certain destination.
func redirectTo(to string) func(http.ResponseWriter, *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		http.Redirect(rw, req, to, http.StatusFound)
	}
}
