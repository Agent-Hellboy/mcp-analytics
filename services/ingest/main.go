package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

type eventPayload struct {
	Timestamp string          `json:"timestamp"`
	Source    string          `json:"source"`
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
}

type ingestServer struct {
	writer       *kafka.Writer
	apiKeys      map[string]struct{}
	jwks         *keyfunc.JWKS
	oidcIssuer   string
	oidcAudience string
}

func main() {
	port := envOr("PORT", "8081")
	metricsPort := envOr("METRICS_PORT", "9091")
	brokers := strings.Split(envOr("KAFKA_BROKERS", "kafka:9092"), ",")
	topic := envOr("KAFKA_TOPIC", "mcp.events")

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

	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		BatchTimeout: 200 * time.Millisecond,
	}

	server := &ingestServer{
		writer:       writer,
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
	mux.Handle("/ingest/events", server.auth(http.HandlerFunc(server.handleEvents)))

	shutdown, err := initTracer("mcp-analytics-ingest")
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

	log.Printf("mcp-analytics-ingest listening on :%s", port)
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

	exporter, err := otlptracehttp.New(context.Background(),
		otlptracehttp.WithEndpoint(strings.TrimPrefix(endpoint, "http://")),
		otlptracehttp.WithInsecure(),
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

func (s *ingestServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var payload eventPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	if payload.Source == "" || payload.EventType == "" || len(payload.Payload) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_fields"})
		return
	}

	if payload.Timestamp == "" {
		payload.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encode_failed"})
		return
	}

	err = s.writer.WriteMessages(r.Context(), kafka.Message{Value: raw})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "enqueue_failed"})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *ingestServer) auth(next http.Handler) http.Handler {
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
