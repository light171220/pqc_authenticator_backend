#!/bin/bash

set -e

echo "Deploying PQC Authenticator..."

# Build the application
echo "Building application..."
make build

# Run tests
echo "Running tests..."
make test

# Create backup before deployment
echo "Creating backup..."
./scripts/backup.sh

# Run database migrations
echo "Running migrations..."
./build/migrate

# Deploy with Docker Compose
echo "Deploying with Docker Compose..."
docker-compose down
docker-compose build
docker-compose up -d

# Wait for service to be ready
echo "Waiting for service to be ready..."
sleep 10

# Health check
echo "Performing health check..."
curl -f http://localhost:8080/health || {
    echo "Health check failed!"
    docker-compose logs
    exit 1
}

echo "Deployment completed successfully!"
echo "Service is available at: http://localhost:8080"