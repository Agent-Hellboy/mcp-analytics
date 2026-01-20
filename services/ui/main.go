package main

import (
	"context"
	"embed"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

//go:embed static/*
var staticFS embed.FS

func main() {
	port := envOr("PORT", "8082")
	apiBase := envOr("API_BASE", "/api")
	apiKey := strings.TrimSpace(os.Getenv("API_KEY"))

	mux := http.NewServeMux()
	mux.HandleFunc("/config.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/javascript")
		config := "window.MCP_API_BASE = \"" + apiBase + "\";"
		if apiKey != "" {
			config += "window.MCP_API_KEY = \"" + apiKey + "\";"
		}
		_, _ = w.Write([]byte(config))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "static/index.html"
		} else {
			path = filepath.ToSlash(filepath.Join("static", path))
		}

		data, err := staticFS.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		if ext := filepath.Ext(path); ext != "" {
			if ct := mime.TypeByExtension(ext); ct != "" {
				w.Header().Set("content-type", ct)
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	shutdown, err := initTracer("mcp-analytics-ui")
	if err != nil {
		log.Printf("otel init failed: %v", err)
	} else {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = shutdown(ctx)
		}()
	}

	log.Printf("mcp-analytics-ui listening on :%s", port)
	handler := otelhttp.NewHandler(logRequests(mux), "http.server")
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		log.Printf("%s %s", r.Method, r.URL.Path)
	})
}

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

func envOr(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func otlpTraceOptions(endpoint string) []otlptracehttp.Option {
	insecure, insecureSet := boolEnv("OTEL_EXPORTER_OTLP_INSECURE")
	if u, err := url.Parse(endpoint); err == nil && u.Scheme != "" {
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
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if insecureSet {
		if insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		return opts
	}
	return append(opts, otlptracehttp.WithInsecure())
}

func boolEnv(key string) (bool, bool) {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		parsed, err := strconv.ParseBool(val)
		if err == nil {
			return parsed, true
		}
	}
	return false, false
}
