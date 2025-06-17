FROM golang:1.21-bookworm AS builder

WORKDIR /app

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    build-essential \
    libsqlite3-dev \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build -ldflags "-extldflags '-static'" -a -o main cmd/server/main.go
RUN CGO_ENABLED=1 go build -ldflags "-extldflags '-static'" -a -o migrate cmd/migrate/main.go

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
    ca-certificates \
    curl \
    tzdata && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/migrate .

RUN mkdir -p /app/data /app/logs
RUN chmod 755 /app/data /app/logs
RUN chmod +x /app/main /app/migrate

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8443/health || exit 1

CMD ["sh", "-c", "./migrate && ./main"]