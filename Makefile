# Variables
CC := clang
CFLAGS := -O2 -Wall
GO := go
RUSTC := cargo
EBPF_SOURCE := exec_logger.c
EBPF_OUT := exec_logger.o
C_SOURCE_DIR := src
C_WRAPPER_OUT := $(C_SOURCE_DIR)/guardianwrap
RUST_DIR := rust_component
GO_DIR := go_orchestration
RUST_TARGET := $(RUST_DIR)/target/release/rust_app
GO_TARGET := $(GO_DIR)/main

# Default target
all: validate_deps ebpf c_wrapper rust go test

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

# Build C Wrapper
c_wrapper: $(C_WRAPPER_OUT)

$(C_WRAPPER_OUT): $(C_SOURCE_DIR)/*.c
	@echo "Building C wrapper..."
	$(CC) $(CFLAGS) -I$(C_SOURCE_DIR)/include -o $(C_WRAPPER_OUT) $(C_SOURCE_DIR)/*.c
	@echo "C wrapper built."

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
test: test_ebpf test_c_wrapper test_rust test_go

test_ebpf:
	@echo "Testing eBPF program..."
	# Placeholder for eBPF testing commands

test_c_wrapper:
	@echo "Testing C wrapper..."
	# Placeholder for C wrapper testing commands

test_rust:
	@echo "Testing Rust component..."
	cd $(RUST_DIR) && $(RUSTC) test

test_go:
	@echo "Testing Go orchestration layer..."
	cd $(GO_DIR) && $(GO) test

# Clean up
clean:
	@echo "Cleaning up build artifacts..."
	rm -f $(EBPF_OUT)
	rm -f $(C_WRAPPER_OUT)
	cd $(RUST_DIR) && $(RUSTC) clean
	rm -f $(GO_TARGET)
	@echo "Cleanup done."

.PHONY: all validate_deps ebpf c_wrapper rust go test test_ebpf test_c_wrapper test_rust test_go clean

