# PQC Authenticator Docker Deployment

This directory contains Docker deployment files for the complete PQC Authenticator stack.

## Quick Start

```bash
# Make the start script executable
chmod +x start.sh

# Start the entire stack
./start.sh
```

## Manual Deployment

```bash
# Start services
docker-compose up --build -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down --volumes
```

## Services

- **Frontend**: React application running on port 3000
- **Backend**: Go API server running on port 8443

## Access Points

- Frontend: http://localhost:3000
- Backend API: http://localhost:8443
- Health Check: http://localhost:8443/health
- Metrics: http://localhost:8443/metrics

## Environment Variables

Copy `.env.example` to `.env` and modify as needed:

```bash
cp .env.example .env
```

## Production Deployment

For production:

1. Update environment variables in `.env`
2. Use proper secrets for JWT_SECRET and ENCRYPTION_KEY
3. Configure proper domains and SSL certificates
4. Set up proper monitoring and logging
5. Use a production database (PostgreSQL recommended)

## Volumes

- `backend_data`: Persistent storage for SQLite database
- `backend_logs`: Application logs

## Network

All services run on the `pqc-network` bridge network for internal communication.

## Health Checks

The backend includes health checks that verify:
- Database connectivity
- Service readiness
- Basic functionality

## Troubleshooting

```bash
# Check service status
docker-compose ps

# View backend logs
docker-compose logs backend

# View frontend logs
docker-compose logs frontend

# Restart a specific service
docker-compose restart backend

# Access backend container
docker-compose exec backend sh

# Access frontend container
docker-compose exec frontend sh
```