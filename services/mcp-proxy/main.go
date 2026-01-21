package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

type analyticsEvent struct {
	Timestamp string         `json:"timestamp"`
	Source    string         `json:"source"`
	EventType string         `json:"event_type"`
	Payload   map[string]any `json:"payload"`
}

type rpcRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type toolParams struct {
	Name string `json:"name"`
}

type proxyServer struct {
	proxy        *httputil.ReverseProxy
	analyticsURL string
	apiKey       string
	source       string
	eventType    string
	stripPrefix  string
	httpClient   *http.Client // Shared HTTP client for analytics emission
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

const maxRPCBodyBytes = 1 << 20

// main initializes and starts the MCP Proxy service.
// It acts as a reverse proxy for MCP servers while capturing analytics.
// Forwards requests to upstream MCP servers and emits analytics events.
func main() {
	port := envOr("PORT", "8091")
	upstream := envOr("UPSTREAM_URL", "http://127.0.0.1:8090")
	analyticsURL := strings.TrimSpace(os.Getenv("ANALYTICS_INGEST_URL"))
	apiKey := strings.TrimSpace(os.Getenv("ANALYTICS_API_KEY"))
	source := envOr("ANALYTICS_SOURCE", "mcp-proxy")
	eventType := envOr("ANALYTICS_EVENT_TYPE", "mcp.request")
	stripPrefix := strings.TrimSpace(os.Getenv("STRIP_PREFIX"))

	target, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("invalid UPSTREAM_URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = otelhttp.NewTransport(http.DefaultTransport)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error: %v", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
	}

	// Create shared HTTP client for analytics emission with connection pooling
	analyticsTransport := otelhttp.NewTransport(&http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	})

	sharedClient := &http.Client{
		Timeout:   3 * time.Second,
		Transport: analyticsTransport,
	}

	srv := &proxyServer{
		proxy:        proxy,
		analyticsURL: analyticsURL,
		apiKey:       apiKey,
		source:       source,
		eventType:    eventType,
		stripPrefix:  stripPrefix,
		httpClient:   sharedClient,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", srv.handleProxy)

	shutdown, err := initTracer("mcp-proxy")
	if err != nil {
		log.Printf("otel init failed: %v", err)
	} else {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = shutdown(ctx)
		}()
	}

	log.Printf("mcp-proxy listening on :%s -> %s", port, upstream)
	handler := otelhttp.NewHandler(mux, "http.server")
	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

// handleProxy handles incoming MCP requests and forwards them to upstream servers.
// It captures request/response metrics, extracts MCP RPC information,
// forwards the request to the configured upstream, and emits analytics events.
func (s *proxyServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	originalPath := r.URL.Path
	rpcMethod, toolName := extractRPCInfo(r)

	if s.stripPrefix != "" && strings.HasPrefix(r.URL.Path, s.stripPrefix) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, s.stripPrefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
	}

	s.proxy.ServeHTTP(recorder, r)

	if s.analyticsURL != "" {
		payload := map[string]any{
			"method":     r.Method,
			"path":       originalPath,
			"query":      r.URL.RawQuery,
			"status":     recorder.status,
			"latency_ms": time.Since(start).Milliseconds(),
			"bytes_in":   maxInt64(r.ContentLength, 0),
			"bytes_out":  recorder.bytes,
		}
		if rpcMethod != "" {
			payload["rpc_method"] = rpcMethod
		}
		if toolName != "" {
			payload["tool_name"] = toolName
		}

		event := analyticsEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Source:    s.source,
			EventType: s.eventType,
			Payload:   payload,
		}

		go s.emit(context.WithoutCancel(r.Context()), event)
	}
}

// emit sends analytics events to the ingest service.
// It asynchronously posts events to the configured analytics endpoint.
// Captures MCP proxy interactions for analytics and monitoring.
func (s *proxyServer) emit(ctx context.Context, event analyticsEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.analyticsURL, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("content-type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("x-api-key", s.apiKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// WriteHeader records the HTTP response status code.
// Implements http.ResponseWriter interface for status tracking.
func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Write records response data and updates byte count.
// Implements http.ResponseWriter interface for response body tracking.
func (r *statusRecorder) Write(data []byte) (int, error) {
	n, err := r.ResponseWriter.Write(data)
	r.bytes += n
	return n, err
}

// Flush forwards flush calls to the underlying ResponseWriter.
// Implements http.Flusher interface for HTTP/1.1 chunked responses.
func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack forwards hijack calls to the underlying ResponseWriter.
// Implements http.Hijacker interface for WebSocket upgrades and similar.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacker not supported")
	}
	return hijacker.Hijack()
}

// Push forwards HTTP/2 server push calls to the underlying ResponseWriter.
// Implements http.Pusher interface for HTTP/2 server push functionality.
func (r *statusRecorder) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := r.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

// extractRPCInfo extracts MCP RPC method and session ID from HTTP requests.
// Parses JSON-RPC request body to identify MCP operations for analytics.
// Returns method name and session ID for tracking purposes.
func extractRPCInfo(r *http.Request) (string, string) {
	if r.Method != http.MethodPost {
		return "", ""
	}
	contentType := r.Header.Get("content-type")
	if contentType != "" && !strings.Contains(contentType, "application/json") {
		return "", ""
	}
	if r.Body == nil || r.ContentLength == 0 || r.ContentLength == -1 || r.ContentLength > maxRPCBodyBytes {
		return "", ""
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		return "", ""
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "", ""
	}

	var toolName string
	if len(req.Params) > 0 {
		var params toolParams
		if err := json.Unmarshal(req.Params, &params); err == nil {
			toolName = params.Name
		}
	}

	return req.Method, toolName
}

// envOr returns the value of an environment variable or a fallback if not set.
// If the environment variable is set to a non-empty value, it returns that value.
// Otherwise, it returns the provided fallback value.
func envOr(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

// maxInt64 returns the maximum of two int64 values.
// Used to ensure size limits don't exceed configured maximums.
func maxInt64(value, fallback int64) int64 {
	if value < 0 {
		return fallback
	}
	return value
}

// initTracer initializes OpenTelemetry tracing for the service.
// It configures OTLP HTTP exporter and sets up the tracer provider.
// Returns a shutdown function to clean up resources and any initialization error.
// If no OTEL_EXPORTER_OTLP_ENDPOINT is configured, returns a no-op shutdown function.
func initTracer(serviceName string) (func(context.Context) error, error) {
	if envName := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); envName != "" {
		serviceName = envName
	}
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}

	opts := otlpTraceOptions(endpoint)
	exporter, err := otlptracehttp.New(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(context.Background(),
		resource.WithAttributes(semconv.ServiceName(serviceName)),
	)
	if err != nil {
		return nil, err
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

// otlpTraceOptions configures OTLP HTTP exporter options.
// It sets up the endpoint URL and configures secure/insecure connections
// based on whether the endpoint uses HTTPS or HTTP.
func otlpTraceOptions(endpoint string) []otlptracehttp.Option {
	insecure, insecureSet := boolEnv("OTEL_EXPORTER_OTLP_INSECURE")
	if u, err := url.Parse(endpoint); err == nil {
		// Handle URLs with schemes (http://host:port/path)
		if u.Scheme != "" && u.Host != "" {
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(u.Host)}
		if u.Path != "" {
			opts = append(opts, otlptracehttp.WithURLPath(u.Path))
		}
		if insecureSet {
			if insecure {
				opts = append(opts, otlptracehttp.WithInsecure())
			}
			return opts
		}
		if u.Scheme == "http" {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		return opts
		// Handle scheme-less endpoints (host:port) that get parsed incorrectly
		// url.Parse("collector:4318") treats "collector" as scheme, leaving Host empty
		if u.Scheme != "" && u.Host == "" {
			// This is a scheme-less endpoint, fall through to treat as host:port
		}
	}

	// Fallback: treat entire endpoint as host:port
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if insecureSet {
		if insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		return opts
	}
	return append(opts, otlptracehttp.WithInsecure())
}

// boolEnv parses a boolean environment variable.
// It returns the parsed boolean value and true if parsing succeeded.
// Returns false, false if the variable is not set or parsing failed.
func boolEnv(key string) (bool, bool) {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		parsed, err := strconv.ParseBool(val)
		if err == nil {
			return parsed, true
		}
	}
	return false, false
}
