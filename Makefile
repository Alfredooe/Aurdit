.PHONY: build run test test-race coverage fmt lint vet clean deps

# Build binary to ./bin directory
build:
	@mkdir -p bin
	go build -o bin/aurdit ./cmd/aurdit

# Run the application
run: build
	./bin/aurdit

# Run tests
test:
	go test -v ./...

# Run tests with race detector
test-race:
	go test -v -race ./...

# Run tests with coverage
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

# Format code
fmt:
	go fmt ./...

# Run linters
lint:
	golangci-lint run

# Run go vet
vet:
	go vet ./...

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out

# Install dependencies
deps:
	go mod download
	go mod tidy
