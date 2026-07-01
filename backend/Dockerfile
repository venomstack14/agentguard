# ============================================================
# AgentGuard — backend Dockerfile
# Multi-stage build: compile a small static binary, then run it
# in a minimal image for fast, cheap deploys (Cloud Run, Render, etc.)
# ============================================================

# --- Stage 1: Build ---
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first so dependency downloads are cached
# separately from source code changes (faster rebuilds)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Compile a statically linked, stripped production binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o app ./cmd/proxy

# --- Stage 2: Run ---
FROM alpine:3.19

WORKDIR /app

# Certificates needed for outbound HTTPS calls (Supabase, Upstash)
RUN apk --no-cache add ca-certificates

COPY --from=builder /app/app .
COPY --from=builder /app/config ./config

EXPOSE 8080

CMD ["./app"]
