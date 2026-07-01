# Stage 1: HARDENED BUILDER
FROM golang:1.22-alpine AS builder

# Set system configurations for a secure, static build
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /app

# Copy dependency manifests first to leverage Docker caching
COPY go.mod go.sum./
RUN go mod download

# Copy the rest of the source code
COPY..

# Compile a statically linked, stripped production binary
RUN go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /app/agentguard-proxy \
   ./cmd/proxy/main.go

# Stage 2: ULTRALIGHT & SECURE RUNTIME
FROM scratch

# Import system SSL/TLS root certificates (needed for secure Out-of-Band API calls)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy our statically compiled proxy binary
COPY --from=builder /app/agentguard-proxy /agentguard-proxy

# Run as non-root (UID 65534 is the default 'nobody' user in Linux)
USER 65534:65534

# Expose the hardened JSON-RPC port
EXPOSE 8080

# Run the proxy engine
ENTRYPOINT ["/agentguard-proxy"]