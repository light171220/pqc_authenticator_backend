# PQC Authenticator - Quantum-Safe 2FA Platform

A production-ready quantum-safe authenticator backend platform built with Go, featuring post-quantum cryptography (PQC) for future-proof security.

## Features

- **Quantum-Safe TOTP**: Uses SHAKE-256 instead of vulnerable HMAC-SHA1
- **Post-Quantum Signatures**: Dilithium signatures for code authenticity
- **Forward Secrecy**: Automatic key rotation using Kyber key exchange
- **Business Integration**: RESTful APIs for enterprise integration
- **Real-time Analytics**: Usage tracking and webhook notifications
- **Secure Backup**: Quantum-safe encrypted backup and recovery

## Quick Start

1. **Install Dependencies**
   ```bash
   go mod download
   ```

2. **Setup Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Initialize Database**
   ```bash
   go run cmd/migrate/main.go
   ```

4. **Run Server**
   ```bash
   go run cmd/server/main.go
   ```

5. **Access API**
   - Server: http://localhost:8080
   - Health Check: http://localhost:8080/health
   - API Documentation: http://localhost:8080/docs

## API Endpoints

### User Management
- `POST /api/v1/users/register` - Register new user
- `POST /api/v1/users/login` - User login
- `GET /api/v1/users/profile` - Get user profile

### TOTP Operations
- `POST /api/v1/totp/generate` - Generate quantum-safe TOTP code
- `POST /api/v1/totp/verify` - Verify TOTP code
- `GET /api/v1/totp/qr/{id}` - Get QR code for setup

### Business API
- `POST /api/business/v1/register` - Register business
- `POST /api/business/v1/verify` - Verify user TOTP
- `GET /api/business/v1/analytics` - Usage analytics

## Configuration

Edit `configs/config.yaml` or use environment variables:

```yaml
server:
  host: "0.0.0.0"
  port: 8080

database:
  type: "sqlite"
  path: "./data/authenticator.db"

security:
  jwt_secret: "your-secret"
  encryption_key: "32-byte-key"
  rate_limit_requests: 100

totp:
  default_period: 30
  key_rotation_interval: "24h"
```

## Security Features

- **Post-Quantum Cryptography**: Dilithium, Kyber, SHAKE-256
- **Rate Limiting**: Protects against brute force attacks
- **Audit Logging**: Comprehensive security event logging
- **Input Validation**: Prevents injection attacks
- **Secure Storage**: Encrypted sensitive data at rest

## Development

### Build
```bash
make build
```

### Test
```bash
make test
```

### Docker
```bash
docker-compose up -d
```

## Production Deployment

1. Set strong secrets in production environment
2. Use HTTPS with proper TLS certificates
3. Configure rate limiting based on your needs
4. Set up proper monitoring and alerting
5. Regular backup of database and keys

## Business Integration

See `docs/INTEGRATION.md` for detailed integration guide.

## License

MIT License - see LICENSE file for details.