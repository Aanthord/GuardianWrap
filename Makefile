# Variables
CC := clang
BPFTOOL := bpftool
GO := go
RUSTC := cargo
EBPF_SOURCE := ebpf/exec_logger.bpf.c
EBPF_OUT := ebpf/exec_logger.bpf.o
EBPF_SKELETON := src/exec_logger.skel.h
C_SOURCE_DIR := src
C_WRAPPER_OUT := guardianwrap
RUST_DIR := rust_component
GO_DIR := go_orchestration
RUST_TARGET := $(RUST_DIR)/target/release/rust_app
GO_TARGET := $(GO_DIR)/guardianwrap

# Docker-related variables
DOCKER_IMAGE_NAME := guardianwrap-dev
DOCKER_CONTAINER_NAME := guardianwrap-build

# Default target
all: validate_deps ebpf c_wrapper rust go

# Validate dependencies
validate_deps:
    @echo "Checking for required tools..."
    @command -v $(CC) >/dev/null || { echo "$(CC) is not installed. Please install it."; exit 1; }
    @command -v $(BPFTOOL) >/dev/null || { echo "$(BPFTOOL) is not installed. Please install it."; exit 1; }
    @command -v $(GO) >/dev/null || { echo "$(GO) is not installed. Please install it."; exit 1; }
    @command -v $(RUSTC) >/dev/null || { echo "$(RUSTC) is not installed. Please install it."; exit 1; }
    @echo "All required tools are installed."

# Build eBPF program and generate skeleton
ebpf: $(EBPF_OUT) $(EBPF_SKELETON)

$(EBPF_OUT): $(EBPF_SOURCE)
    @echo "Building eBPF program..."
    $(CC) -O2 -g -Wall -target bpf -c $< -o $@
    @echo "eBPF program built."

$(EBPF_SKELETON): $(EBPF_OUT)
    @echo "Generating eBPF skeleton..."
    $(BPFTOOL) gen skeleton $< > $@
    @echo "eBPF skeleton generated."

# Build C Wrapper
c_wrapper: $(C_WRAPPER_OUT)

$(C_WRAPPER_OUT): $(C_SOURCE_DIR)/*.c $(EBPF_SKELETON)
    @echo "Building C wrapper..."
    $(CC) $(C_SOURCE_DIR)/*.c -lelf -lz -o $@
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

# Build target (added)
build: ebpf c_wrapper rust go
    @echo "Build completed successfully."

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
    cd $(GO_DIR) && $(GO) test ./...

# Clean up
clean:
    @echo "Cleaning up build artifacts..."
    rm -f $(EBPF_OUT) $(C_WRAPPER_OUT) $(EBPF_SKELETON)
    cd $(RUST_DIR) && $(RUSTC) clean
    rm -f $(GO_TARGET)
    @echo "Cleanup done."

# Docker commands
docker-build:
    docker build -t $(DOCKER_IMAGE_NAME) .

docker-make-all: docker-build
    docker run --rm --name $(DOCKER_CONTAINER_NAME) -v "$(PWD)":/usr/src/app $(DOCKER_IMAGE_NAME) make all

.PHONY: all validate_deps ebpf c_wrapper rust go test test_ebpf test_c_wrapper test_rust test_go clean docker-build docker-make-all
