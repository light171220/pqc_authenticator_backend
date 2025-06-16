.PHONY: build run test clean migrate docker-build docker-run docker-stop setup dev install-tools help
.PHONY: build-prod run-prod setup-secrets setup-certs lint fmt check release

# Keep original naming for compatibility
BINARY_NAME := pqc-authenticator
APP_NAME := pqc-authenticator
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags="-w -s -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

# Build settings
CGO_ENABLED := 1
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

# Directories (keep original structure)
BUILD_DIR := build
DATA_DIR := data
LOG_DIR := logs
CERT_DIR := certs
SECRET_DIR := secrets

help: ## Show available commands
	@echo "Available commands:"
	@echo " build          - Build the application"
	@echo " run            - Run the application"
	@echo " test           - Run tests"
	@echo " migrate        - Run database migrations"
	@echo " clean          - Clean build directory"
	@echo " docker-build   - Build Docker image"
	@echo " docker-run     - Run with Docker Compose"
	@echo " docker-stop    - Stop Docker containers"
	@echo " setup          - Setup development environment"
	@echo " dev            - Start development server with hot reload"
	@echo " install-tools  - Install development tools"
	@echo ""
	@echo "Production commands:"
	@echo " build-prod     - Build optimized production binary"
	@echo " run-prod       - Run in production mode with TLS"
	@echo " setup-secrets  - Generate production secrets"
	@echo " setup-certs    - Generate TLS certificates"
	@echo " lint           - Run code linting"
	@echo " fmt            - Format code"
	@echo " check          - Run all checks (fmt, lint, test)"
	@echo " release        - Create release build"

# Original commands (keep exact same behavior)
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
	@rm -rf $(DATA_DIR)/

docker-build:
	@echo "Building Docker image..."
	@docker build -t $(BINARY_NAME) .

docker-run:
	@echo "Running with Docker Compose..."
	@docker-compose up -d

docker-stop:
	@echo "Stopping Docker containers..."
	@docker-compose down

setup:
	@echo "Setting up development environment..."
	@if [ -f .env.example ] && [ ! -f .env ]; then cp .env.example .env; fi
	@mkdir -p $(DATA_DIR)
	@mkdir -p $(LOG_DIR)
	@go mod download
	@make migrate

dev:
	@echo "Starting development server with hot reload..."
	@air

install-tools:
	@echo "Installing development tools..."
	@go install github.com/cosmtrek/air@latest

# New production-ready commands
build-prod: ## Build optimized production binary
	@echo "Building $(BINARY_NAME) version $(VERSION) for production..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		$(LDFLAGS) \
		-a -installsuffix cgo \
		-o $(BUILD_DIR)/$(BINARY_NAME) \
		./cmd/server
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		$(LDFLAGS) \
		-a -installsuffix cgo \
		-o $(BUILD_DIR)/migrate \
		./cmd/migrate
	@echo "Production build completed: $(BUILD_DIR)/$(BINARY_NAME)"

setup-secrets: ## Generate production secrets
	@echo "Setting up production secrets..."
	@mkdir -p $(SECRET_DIR)
	@chmod 750 $(SECRET_DIR)
	@if [ ! -f $(SECRET_DIR)/jwt_secret.txt ]; then \
		openssl rand -hex 64 > $(SECRET_DIR)/jwt_secret.txt; \
		chmod 600 $(SECRET_DIR)/jwt_secret.txt; \
		echo "JWT secret generated"; \
	fi
	@if [ ! -f $(SECRET_DIR)/encryption_key.txt ]; then \
		openssl rand -hex 64 > $(SECRET_DIR)/encryption_key.txt; \
		chmod 600 $(SECRET_DIR)/encryption_key.txt; \
		echo "Encryption key generated"; \
	fi
	@echo "Production secrets ready"

setup-certs: ## Generate TLS certificates
	@echo "Setting up TLS certificates..."
	@mkdir -p $(CERT_DIR)
	@if [ ! -f $(CERT_DIR)/server.crt ]; then \
		openssl req -x509 -newkey rsa:4096 -keyout $(CERT_DIR)/server.key -out $(CERT_DIR)/server.crt \
			-days 365 -nodes -subj "/C=US/ST=Dev/L=Dev/O=PQC-Auth/CN=localhost"; \
		chmod 600 $(CERT_DIR)/server.key; \
		echo "TLS certificates generated for development"; \
		echo "WARNING: Use proper certificates for production!"; \
	fi

run-prod: build-prod setup-secrets setup-certs ## Run in production mode
	@echo "Starting $(BINARY_NAME) in production mode..."
	@mkdir -p $(DATA_DIR) $(LOG_DIR)
	@export JWT_SECRET=$(cat $(SECRET_DIR)/jwt_secret.txt) && \
	 export ENCRYPTION_KEY=$(cat $(SECRET_DIR)/encryption_key.txt) && \
	 export SERVER_MODE=release && \
	 export LOG_LEVEL=info && \
	 export DATABASE_PATH=$(DATA_DIR)/authenticator.db && \
	 export TLS_CERT_FILE=$(CERT_DIR)/server.crt && \
	 export TLS_KEY_FILE=$(CERT_DIR)/server.key && \
	 $(BUILD_DIR)/$(BINARY_NAME)

lint: ## Run code linting
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		go vet ./...; \
	fi

fmt: ## Format code
	@echo "Formatting code..."
	@go fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	else \
		echo "goimports not installed. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi

check: fmt lint test ## Run all checks

release: clean check build-prod ## Create release build
	@echo "Creating release archive..."
	@mkdir -p release
	@tar -czf release/$(BINARY_NAME)-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz \
		-C $(BUILD_DIR) $(BINARY_NAME) migrate
	@echo "Release created: release/$(BINARY_NAME)-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz"

# Enhanced development setup
dev-setup: install-tools setup setup-secrets ## Complete development setup
	@echo "Development environment setup completed"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Run 'make dev' to start development server with hot reload"
	@echo "  2. Run 'make run-prod' to test production mode locally"
	@echo "  3. Visit http://localhost:8443/health to verify"

# Docker enhancements
docker-compose-logs: ## Show docker-compose logs
	@docker-compose logs -f

docker-clean: ## Clean Docker images and containers
	@echo "Cleaning Docker resources..."
	@docker-compose down --volumes --remove-orphans
	@docker image prune -f
	@docker volume prune -f

# Testing enhancements  
test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out ./...
	@if command -v go >/dev/null 2>&1; then \
		go tool cover -html=coverage.out -o coverage.html; \
		echo "Coverage report: coverage.html"; \
	fi

benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./...

# Utility commands
mod-tidy: ## Tidy go modules
	@echo "Tidying go modules..."
	@go mod tidy

update-deps: ## Update dependencies
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

security-scan: ## Run security scan (if gosec is installed)
	@if command -v gosec >/dev/null 2>&1; then \
		echo "Running security scan..."; \
		gosec ./...; \
	else \
		echo "gosec not installed. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi