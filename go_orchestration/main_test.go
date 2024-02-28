// main_test.go
package main

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Clean up environment variables to ensure a clean environment for testing
	os.Clearenv()

	// Test loading configuration from environment variables
	config := loadConfig()
	expectedHTTPPort := "8080"
	expectedJaegerEndpoint := "http://localhost:14268/api/traces"

	if config.HTTPPort != expectedHTTPPort {
		t.Errorf("Expected HTTPPort: %s, got: %s", expectedHTTPPort, config.HTTPPort)
	}
	if config.JaegerEndpoint != expectedJaegerEndpoint {
		t.Errorf("Expected JaegerEndpoint: %s, got: %s", expectedJaegerEndpoint, config.JaegerEndpoint)
	}
}

func TestCreateEnvFile(t *testing.T) {
	// Test creating .env file
	createEnvFile()

	// Check if .env file exists
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		t.Errorf("Expected .env file to be created, but it doesn't exist")
	}
}

func TestLoadEBPFProgram_Main(t *testing.T) {
	// Test loading and attaching eBPF program from main.go
	module := loadEBPFProgram()
	defer module.Close() // Clean up resources

	// Check if eBPF program is successfully loaded and attached
	// Add assertions based on specific behavior of the loadEBPFProgram function
	// For example, check if certain BPF objects are loaded, etc.
}

func TestHandleRequests(t *testing.T) {
	// Test handling HTTP requests
	// Implement tests to check if the expected routes are registered and served correctly
	// For example, make HTTP requests to each endpoint and validate the responses
	// Ensure that Prometheus metrics handler and Swagger documentation handler are registered correctly
}
