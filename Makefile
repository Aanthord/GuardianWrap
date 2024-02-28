# Variables
CC := clang
CFLAGS := -O2 -Wall
GO := go
RUSTC := cargo
EBPF_SOURCE := exec_logger.c
EBPF_OUT := exec_logger.o
RUST_DIR := rust_component
GO_DIR := go_orchestration
RUST_TARGET := $(RUST_DIR)/target/release/rust_app
GO_TARGET := $(GO_DIR)/main

# Default target
all: validate_deps ebpf rust go test

# Validate dependencies
validate_deps:
	@echo "Checking for required tools..."
	@command -v $(CC) >/dev/null || { echo "$(CC) is not installed. Please install it."; exit 1; }
	@command -v $(GO) >/dev/null || { echo "$(GO) is not installed. Please install it."; exit 1; }
	@command -v $(RUSTC) >/dev/null || { echo "$(RUSTC) is not installed. Please install it."; exit 1; }
	@command -v inotifywait >/dev/null || { echo "inotifywait is not installed. Please install it."; exit 1; }
	@echo "All required tools are installed."

# Build eBPF program
ebpf: $(EBPF_OUT)

$(EBPF_OUT): $(EBPF_SOURCE)
	@echo "Building eBPF program..."
	$(CC) $(CFLAGS) -target bpf -c $< -o $@
	@echo "eBPF program built."

# Build Rust component
rust:
	@echo "Building Rust component..."
	cd $(RUST_DIR) && $(RUSTC) build --release
	@echo "Rust component built."

# Build Go orchestration layer
go:
	@echo "Building Go orchestration layer..."
	cd $(GO_DIR) && $(GO) build -o $(GO_TARGET)
	@echo "Go orchestration layer built."

# Test targets for each component
test: test_ebpf test_rust test_go

test_ebpf:
	@echo "Testing eBPF program..."
	# Placeholder for eBPF testing commands

test_rust:
	@echo "Testing Rust component..."
	cd $(RUST_DIR) && $(RUSTC) test

test_go:
	@echo "Testing Go orchestration layer..."
	cd $(GO_DIR) && $(GO) test

# Watch targets for each component
watch_ebpf:
	@echo "Watching eBPF source for changes..."
	@while inotifywait -e modify $(EBPF_SOURCE); do make ebpf; done

watch_rust:
	@echo "Watching Rust source for changes..."
	@while inotifywait -r -e modify $(RUST_DIR)/src; do make rust; done

watch_go:
	@echo "Watching Go source for changes..."
	@while inotifywait -r -e modify $(GO_DIR)/*.go; do make go; done

# Unified watch command
watch_all:
	@echo "Watching all components for changes..."
	@($(MAKE) watch_ebpf & $(MAKE) watch_rust & $(MAKE) watch_go & wait)

# Clean up
clean:
	@echo "Cleaning up build artifacts..."
	rm -f $(EBPF_OUT)
	cd $(RUST_DIR) && $(RUSTC) clean
	rm -f $(GO_TARGET)
	@echo "Cleanup done."

.PHONY: all validate_deps ebpf rust go test test_ebpf test_rust test_go clean watch_ebpf watch_rust watch_go watch_all

