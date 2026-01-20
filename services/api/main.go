package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

type eventRow struct {
	Timestamp time.Time       `json:"timestamp"`
	Source    string          `json:"source"`
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
}

type apiServer struct {
	db           clickhouse.Conn
	dbName       string
	apiKeys      map[string]struct{}
	jwks         *keyfunc.JWKS
	oidcIssuer   string
	oidcAudience string
}

func main() {
	port := envOr("PORT", "8080")
	metricsPort := envOr("METRICS_PORT", "9090")
	clickhouseAddr := envOr("CLICKHOUSE_ADDR", "clickhouse:9000")
	dbName := envOr("CLICKHOUSE_DB", "mcp")

	apiKeys := map[string]struct{}{}
	for _, key := range strings.Split(envOr("API_KEYS", ""), ",") {
		key = strings.TrimSpace(key)
		if key != "" {
			apiKeys[key] = struct{}{}
		}
	}

	jwksURL := strings.TrimSpace(os.Getenv("OIDC_JWKS_URL"))
	jwks := (*keyfunc.JWKS)(nil)
	if jwksURL != "" {
		var err error
		jwks, err = keyfunc.Get(jwksURL, keyfunc.Options{RefreshInterval: 10 * time.Minute})
		if err != nil {
			log.Fatalf("failed to load JWKS: %v", err)
		}
	}

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{clickhouseAddr},
		Auth: clickhouse.Auth{
			Database: dbName,
		},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("failed to connect to clickhouse: %v", err)
	}

	server := &apiServer{
		db:           conn,
		dbName:       dbName,
		apiKeys:      apiKeys,
		jwks:         jwks,
		oidcIssuer:   strings.TrimSpace(os.Getenv("OIDC_ISSUER")),
		oidcAudience: strings.TrimSpace(os.Getenv("OIDC_AUDIENCE")),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.Handle("/events", server.auth(http.HandlerFunc(server.handleEvents)))
	mux.Handle("/stats", server.auth(http.HandlerFunc(server.handleStats)))
	mux.Handle("/api/events", server.auth(http.HandlerFunc(server.handleEvents)))
	mux.Handle("/api/stats", server.auth(http.HandlerFunc(server.handleStats)))

	shutdown, err := initTracer("mcp-analytics-api")
	if err != nil {
		log.Printf("otel init failed: %v", err)
	} else {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = shutdown(ctx)
		}()
	}

	go func() {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(":"+metricsPort, metricsMux); err != nil {
			log.Printf("metrics server stopped: %v", err)
		}
	}()

	log.Printf("mcp-analytics-api listening on :%s", port)
	handler := otelhttp.NewHandler(logRequests(mux), "http.server")
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func initTracer(serviceName string) (func(context.Context) error, error) {
	if envName := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); envName != "" {
		serviceName = envName
	}
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}

	// Parse and extract host:port if a full URL is provided
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		if u, err := url.Parse(endpoint); err == nil {
			endpoint = u.Host
		}
	}

	exporter, err := otlptracehttp.New(context.Background(),
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(), // TODO: make configurable for TLS
	)
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

func (s *apiServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit := clampInt(queryInt(r, "limit", 100), 1, 1000)

	query := "SELECT timestamp, source, event_type, payload FROM " + s.dbName + ".events ORDER BY timestamp DESC LIMIT ?"
	rows, err := s.db.Query(r.Context(), query, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query_failed"})
		return
	}
	defer rows.Close()

	events := make([]eventRow, 0, limit)
	for rows.Next() {
		var row eventRow
		var payloadStr string
		if err := rows.Scan(&row.Timestamp, &row.Source, &row.EventType, &payloadStr); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "scan_failed"})
			return
		}
		if json.Valid([]byte(payloadStr)) {
			row.Payload = json.RawMessage(payloadStr)
		} else {
			raw, _ := json.Marshal(payloadStr)
			row.Payload = raw
		}
		events = append(events, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *apiServer) handleStats(w http.ResponseWriter, r *http.Request) {
	query := "SELECT count() FROM " + s.dbName + ".events"
	row := s.db.QueryRow(r.Context(), query)
	var count uint64
	if err := row.Scan(&count); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query_failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"events_total": count})
}

func (s *apiServer) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.apiKeys) > 0 {
			apiKey := strings.TrimSpace(r.Header.Get("x-api-key"))
			if apiKey != "" {
				if _, ok := s.apiKeys[apiKey]; ok {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		token := extractBearer(r.Header.Get("authorization"))
		if token != "" && s.jwks != nil {
			parsed, err := jwt.Parse(token, s.jwks.Keyfunc)
			if err == nil && parsed.Valid {
				if s.oidcIssuer != "" || s.oidcAudience != "" {
					claims, ok := parsed.Claims.(jwt.MapClaims)
					if !ok {
						writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
						return
					}
					if s.oidcIssuer != "" && claims["iss"] != s.oidcIssuer {
						writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
						return
					}
					if s.oidcAudience != "" {
						if !audienceMatches(claims["aud"], s.oidcAudience) {
							writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
							return
						}
					}
				}
				next.ServeHTTP(w, r)
				return
			}
		}

		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	})
}

func audienceMatches(audClaim any, expected string) bool {
	switch aud := audClaim.(type) {
	case string:
		return aud == expected
	case []any:
		for _, item := range aud {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func extractBearer(auth string) string {
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func envOr(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func queryInt(r *http.Request, key string, fallback int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func clampInt(value, minVal, maxVal int) int {
	if value < minVal {
		return minVal
	}
	if value > maxVal {
		return maxVal
	}
	return value
}
