package main

// @title Guardian Wrapper API
// @description API for Guardian Wrapper, providing system monitoring and security features.
// @version 1.0
// @host localhost:8080
// @BasePath /
import (
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/joho/godotenv"
    _ "github.com/lib/pq" // Use underscore import for pq to solely initialize its drivers without using it directly
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/swaggo/http-swagger"
    _ "github.com/yourusername/guardianwrapper/docs" // Import generated Swagger docs
    "golang.org/x/sys/unix"
)

// Config holds the application configuration, sourced from environment variables.
type Config struct {
    HTTPPort string // Port for the HTTP server to listen on
    DBConn   string // Database connection string, unused in this snippet but included for completeness
}

// loadConfig loads application configuration, prioritizing environment variables over default values.
func loadConfig() *Config {
    _ = godotenv.Load() // Load .env file, if present
    return &Config{
        HTTPPort: os.Getenv("HTTP_PORT"),
        DBConn:   os.Getenv("DB_CONN"),
    }
}

func main() {
    config := loadConfig()
    setupSignalHandling()
    go startHTTPServer(config.HTTPPort)
    loadAndAttachEBPF()

    <-signalChan // Wait for termination signal
    cleanup()
}

var signalChan = make(chan os.Signal, 1)

func setupSignalHandling() {
    signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
}

// startHTTPServer initializes and starts the HTTP server, setting up routes and handlers.
func startHTTPServer(port string) {
    http.HandleFunc("/api", apiHandler)
    http.Handle("/metrics", promhttp.Handler()) // Serve Prometheus metrics
    http.HandleFunc("/swagger/*any", httpSwagger.WrapHandler) // Serve Swagger UI

    log.Printf("Starting HTTP server on port %s", port)
    if err := http.ListenAndServe(":"+port, nil); err != nil {
        log.Fatalf("Failed to start HTTP server: %v", err)
    }
}

// @Summary Example API endpoint
// @Description Provides an example API response.
// @Accept  json
// @Produce  json
// @Success 200 {string} string "API response"
// @Router /api [get]
func apiHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("API response"))
}

// loadAndAttachEBPF loads and attaches the eBPF program to the specified hook.
func loadAndAttachEBPF() {
    coll, err := ebpf.LoadCollection(os.Getenv("EXEC_LOGGER_PATH"))
    if err != nil {
        log.Fatalf("Error loading eBPF collection: %v", err)
    }
    defer coll.Close()

    tp, err := link.Tracepoint("syscalls", "sys_enter_exec", coll.Programs["exec_logger"])
    if err != nil {
        log.Fatalf("Error attaching tracepoint: %v", err)
    }
    defer tp.Close()

    log.Println("eBPF program loaded and attached")
}

func cleanup() {
    // Placeholder for cleanup logic
    log.Println("Cleanup complete. Exiting...")
}
