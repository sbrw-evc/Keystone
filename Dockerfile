# Keystone (formerly SPA): one image with the Go server and the built web app.
#   docker build -t keystone .
#   docker run -p 8080:8080 -v keystone-data:/data keystone   (then open it and follow the setup wizard)

# The web app and the server are built on the platform of the builder and the binary is cross-compiled for the
# target, so a multi-platform build (amd64 + arm64) needs no emulation.

# 1. The web app (React + Vite) → /src/web/dist (the same files for every platform)
FROM --platform=$BUILDPLATFORM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# 2. The server → /out/keystone (static, no cgo)
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS server
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/keystone ./cmd/keystone \
 && mkdir -p /out/data

# 3. A minimal image: the binary, the web app, CA certificates, a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=server /out/keystone /app/keystone
COPY --from=web /src/web/dist /app/web
# /data: bootstrap.json, the AppRole secret_id, the setup code (a volume in docker-compose.yml)
COPY --from=server --chown=nonroot:nonroot /out/data /data
ENV SPA_WEB_DIR=/app/web \
    SPA_LISTEN=:8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/keystone"]
