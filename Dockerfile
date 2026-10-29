# syntax=docker/dockerfile:1

# Production image. Built in GitHub Actions and published to GHCR: the server
# never compiles, it only pulls.

FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# genkey ships in the image so the signing key can be produced on the server without a
# Go toolchain (docker run --rm <image> /app/genkey).
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-api ./cmd/api \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/genkey ./cmd/genkey

FROM alpine:3.22 AS runner
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=builder /out/auth-api /out/genkey /app/
USER app
ENV HTTP_ADDR=:8080 APP_ENV=production
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/app/auth-api"]
