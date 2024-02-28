package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/swaggo/http-swagger"
	"github.com/urfave/negroni"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/semconv"
	"go.opentelemetry.io/otel/trace"
)

var (
	// Verbose logger to print detailed logs.
	verboseLogger = log.New(os.Stdout, "[VERBOSE] ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
)

// Config struct to hold configuration variables.
type Config struct {
	HTTPPort       string
	JaegerEndpoint string
}

// loadConfig loads configuration from environment variables or a .env file.
func loadConfig() *Config {
	// Load environment variables from .env file.
	err := godotenv.Load()
	if err != nil {
		log.Printf("Error loading .env file: %s\n", err)
	}

	// Initialize configuration with default values or environment variables.
	config := &Config{
		HTTPPort:       getEnv("HTTP_PORT", "8080"),
		JaegerEndpoint: getEnv("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
	}

	return config
}

// createEnvFile creates a .env file with default values if it doesn't exist.
func createEnvFile() {
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		file, err := os.Create(".env")
		if err != nil {
			log.Fatalf("Error creating .env file: %s\n", err)
		}
		defer file.Close()

		// Write default configuration to .env file.
		_, err = file.WriteString("HTTP_PORT=8080\n")
		if err != nil {
			log.Fatalf("Error writing to .env file: %s\n", err)
		}

		// Write Jaeger endpoint default configuration to .env file.
		_, err = file.WriteString("JAEGER_ENDPOINT=http://localhost:14268/api/traces\n")
		if err != nil {
			log.Fatalf("Error writing to .env file: %s\n", err)
		}
	}
}

// loadEBPFProgram loads and attaches the eBPF program to a tracepoint for execve system calls.
func loadEBPFProgram() *bpf.Module {
	// Read the eBPF program source from a file.
	source, err := os.ReadFile("exec_logger.c")
	if err != nil {
		log.Fatalf("Failed to read eBPF program source: %s\n", err)
	}

	// Create a new BCC module with the eBPF program source.
	m := bpf.NewModule(string(source), []string{})
	defer m.Close()

	// Load the eBPF program into the kernel.
	tp, err := m.LoadTracepoint("log_exec")
	if err != nil {
		log.Fatalf("Failed to load exec logger tracepoint: %s\n", err)
	}

	// Attach the loaded program to the execve tracepoint.
	err = m.AttachTracepoint("syscalls:sys_enter_execve", tp)
	if err != nil {
		log.Fatalf("Failed to attach to execve tracepoint: %s\n", err)
	}

	// Print a confirmation message indicating successful loading and attachment.
	fmt.Println("eBPF program loaded and attached.")
	verboseLogger.Println("eBPF program loaded and attached.")
	return m
}

// registerPrometheusMetrics registers Prometheus metrics.
func registerPrometheusMetrics() {
	// Define and register custom metrics.
	httpRequestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests.",
	}, []string{"method", "status"})
	prometheus.MustRegister(httpRequestsTotal)
}

// handleRequests registers HTTP handlers and routes.
func handleRequests() {
	// Initialize OpenTelemetry exporter for Jaeger.
	exp, err := jaeger.NewRawExporter(
		jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(config.JaegerEndpoint)),
	)
	if err != nil {
		log.Fatalf("Failed to create Jaeger exporter: %v", err)
	}
	tp := trace.NewTracerProvider(
		trace.WithSampler(trace.AlwaysSample()),
		trace.WithSpanProcessor(trace.NewBatchSpanProcessor(exp)),
		trace.WithResource(resource.NewWithAttributes(
			semconv.ServiceNameKey.String("your-service-name"),
		)),
	)
	otel.SetTracerProvider(tp)
	propagator := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	otel.SetTextMapPropagator(propagator)

	// Register Prometheus metrics handler.
	http.Handle("/metrics", promhttp.Handler())

	// Register Swagger documentation handler.
	http.HandleFunc("/swagger/", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8080/swagger/doc.json"),
	))

	// @Summary Health check
	// @Description Returns a simple health status message
	// @ID health-check
	// @Produce json
	// @Success 200 {string} string "OK"
	// @Router /health [get]
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Increment Prometheus metric for HTTP requests.
		httpRequestsTotal.WithLabelValues(r.Method, "200").Inc()

		// Write response.
		fmt.Fprintf(w, "OK")
	})
}

func main() {
	// Create .env file with default values if it doesn't exist.
	createEnvFile()

	// Load configuration.
	config := loadConfig()

	// Initialize Prometheus metrics.
	registerPrometheusMetrics()

	// Load and attach the eBPF program on startup.
	loadEBPFProgram()

	// Handle HTTP requests.
	handleRequests()

	// Create a Negroni instance for middleware management.
	n := negroni.New()

	// Add middleware to Negroni.
	n.Use(negroni.NewRecovery())
	n.UseHandler(http.DefaultServeMux)

	// Log the start of the HTTP server.
	log.Printf("HTTP server started on :%s\n", config.HTTPPort)
	verboseLogger.Printf("HTTP server started on :%s\n", config.HTTPPort)

	// Start listening and serving HTTP requests using Negroni.
	go func() {
		if err := http.ListenAndServe(":"+config.HTTPPort, n); err != nil {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	// Prepare for graceful shutdown by listening for interrupt signals.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig // Wait for signal.

	// Log server shutdown and exit.
	log.Println("Exiting...")
	verboseLogger.Println("Exiting...")
}
