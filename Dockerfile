FROM golang:1.21-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev sqlite-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o main cmd/server/main.go
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o migrate cmd/migrate/main.go

FROM alpine:latest

RUN apk add --no-cache sqlite ca-certificates curl

WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/migrate .
COPY --from=builder /app/configs ./configs

RUN mkdir -p /app/data /app/logs

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["./main"]