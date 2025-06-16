#!/bin/bash

set -e

echo "Setting up PQC Authenticator..."

# Create necessary directories
mkdir -p data logs

# Copy environment file if it doesn't exist
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env file from template. Please update with your configuration."
fi

# Download dependencies
echo "Downloading Go dependencies..."
go mod download

# Run database migrations
echo "Running database migrations..."
go run cmd/migrate/main.go

# Generate initial encryption keys if they don't exist
if [ ! -f data/encryption.key ]; then
    echo "Generating encryption keys..."
    openssl rand -base64 32 > data/encryption.key
    echo "Generated encryption key in data/encryption.key"
fi

echo "Setup complete!"
echo ""
echo "To start the server:"
echo "  go run cmd/server/main.go"
echo ""
echo "Or with make:"
echo "  make run"
echo ""
echo "Don't forget to update your .env file with proper secrets for production!"