package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "github.com/gorilla/mux"
    "github.com/gorilla/websocket"
    "github.com/iovisor/gobpf/bcc"
)

// Load and attach the eBPF program to the tracepoint for execve system calls.
func loadEBPFProgram() {
    source, err := os.ReadFile("exec_logger.c")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read eBPF program source: %s\n", err)
        os.Exit(1)
    }

    m := bcc.NewModule(string(source), []string{})
    defer m.Close()

    tp, err := m.LoadTracepoint("log_exec")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load exec logger tracepoint: %s\n", err)
        os.Exit(1)
    }

    err = m.AttachTracepoint("syscalls:sys_enter_execve", tp)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to attach to execve tracepoint: %s\n", err)
        os.Exit(1)
    }

    fmt.Println("eBPF program loaded and attached.")
}

// WebSocket handler for streaming eBPF events to a web client.
func eventWebSocket(w http.ResponseWriter, r *http.Request) {
    upgrader := websocket.Upgrader{
        ReadBufferSize:  1024,
        WriteBufferSize: 1024,
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()

    alertChannel := make(chan Alert)
    go alertWebSocket(conn, alertChannel)

    // Imagine this loop listens for new eBPF events and sends them to the client.
    for {
        event := getNextEvent()
        if err := conn.WriteJSON(event); err != nil {
            log.Println(err)
            break
        }
    }
}

// Separate goroutine for handling alerts and sending them over the same WebSocket connection.
func alertWebSocket(conn *websocket.Conn, alertChannel <-chan Alert) {
    for alert := range alertChannel {
        if err := conn.WriteJSON(alert); err != nil {
            log.Println("Error sending alert over WebSocket:", err)
            break
        }
    }
}

// Alert struct for demonstration purposes.
type Alert struct {
    Type    string `json:"type"`
    Message string `json:"message"`
}

func main() {
    loadEBPFProgram()

    // Setting up an HTTP server and routes for querying eBPF events.
    router := mux.NewRouter()
    router.HandleFunc("/events/ws", eventWebSocket).Methods("GET")

    log.Println("HTTP server started on :8080")
    err := http.ListenAndServe(":8080", router)
    if err != nil {
        log.Fatal("ListenAndServe: ", err)
    }

    // Graceful shutdown handling.
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
    <-sig

    fmt.Println("Exiting...")
}

