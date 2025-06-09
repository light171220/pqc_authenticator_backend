.PHONY: build run test clean migrate docker-build docker-run

BINARY_NAME=pqc-authenticator
BUILD_DIR=build

build:
	@echo "Building application..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) cmd/server/main.go
	@go build -o $(BUILD_DIR)/migrate cmd/migrate/main.go

run:
	@echo "Running application..."
	@go run cmd/server/main.go

test:
	@echo "Running tests..."
	@go test -v ./...

migrate:
	@echo "Running database migrations..."
	@go run cmd/migrate/main.go

clean:
	@echo "Cleaning build directory..."
	@rm -rf $(BUILD_DIR)
	@rm -rf data/

docker-build:
	@echo "Building Docker image..."
	@docker build -t pqc-authenticator .

docker-run:
	@echo "Running with Docker Compose..."
	@docker-compose up -d

docker-stop:
	@echo "Stopping Docker containers..."
	@docker-compose down

setup:
	@echo "Setting up development environment..."
	@cp .env.example .env
	@mkdir -p data
	@mkdir -p logs
	@go mod download
	@make migrate

dev:
	@echo "Starting development server with hot reload..."
	@air

install-tools:
	@echo "Installing development tools..."
	@go install github.com/cosmtrek/air@latest

help:
	@echo "Available commands:"
	@echo "  build        - Build the application"
	@echo "  run          - Run the application"
	@echo "  test         - Run tests"
	@echo "  migrate      - Run database migrations"
	@echo "  clean        - Clean build directory"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with Docker Compose"
	@echo "  docker-stop  - Stop Docker containers"
	@echo "  setup        - Setup development environment"
	@echo "  dev          - Start development server with hot reload"
	@echo "  install-tools- Install development tools"