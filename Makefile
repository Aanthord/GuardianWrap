# Variables
CC := clang

#clang -O2 -Wall -Iinclude -I/usr/src/linux-headers-5.15.0-97/include/ -I/usr/src/linux-headers-5.15.0-97/arch/x86/include/ -I/usr/src/linux-headers-5.15.0-97/arch/x86/include/uapi/ -I/usr/include/x86_64-linux-gnu/asm/ -target bpf -c ebpf/exec_logger.c -o exec_logger.o
#CLFAGS := -O2 -Wall -target bpf -I/usr/include/bpf
#CLFAGS := -O2 -Wall -Iinclude -I/usr/src/linux-headers-5.15.0-97/include/ -I/usr/src/linux-headers-5.15.0-97/arch/x86/include/ -I/usr/src/linux-headers-5.15.0-97/arch/x86/include/uapi/ -I/usr/include/x86_64-linux-gnu/asm/
#CFLAGS := -O2 -Wall -Iinclude -I/usr/src/linux-headers-5.15.0-97/include/ -I/usr/src/linux-headers-5.15.0-97/arch/x86/include/
GO := go
RUSTC := cargo
EBPF_SOURCE := ebpf/exec_logger.c
EBPF_OUT := exec_logger.o
C_SOURCE_DIR := src
C_WRAPPER_OUT := guardianwrap
RUST_DIR := rust_component
GO_DIR := go_orchestration
RUST_TARGET := $(RUST_DIR)/target/release/rust_app
GO_TARGET := $(GO_DIR)/main

# Docker-related variables
DOCKER_IMAGE_NAME := guardianwrap-dev
DOCKER_CONTAINER_NAME := guardianwrap-build

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
	$(CC) $(CFLAGS) -o $@ $(C_SOURCE_DIR)/*.c
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
	rm -f $(EBPF_OUT) $(C_WRAPPER_OUT)
	cd $(RUST_DIR) && $(RUSTC) clean
	rm -f $(GO_TARGET)
	@echo "Cleanup done."

# Docker commands
# Build the Docker image
docker-build:
	docker build -t $(DOCKER_IMAGE_NAME) .

# Run 'make all' inside the Docker container
docker-make-all: docker-build
	docker run --rm --name $(DOCKER_CONTAINER_NAME) -v "$(PWD)":/usr/src/app $(DOCKER_IMAGE_NAME) make all

# Optional: a generic target to run any make command inside Docker
docker-%: docker-build
	docker run --rm --name $(DOCKER_CONTAINER_NAME)-$* -v "$(PWD)":/usr/src/app $(DOCKER_IMAGE_NAME) make $*

.PHONY: all validate_deps ebpf c_wrapper rust go test test_ebpf test_c_wrapper test_rust test_go clean docker-build docker-make-all docker-%

