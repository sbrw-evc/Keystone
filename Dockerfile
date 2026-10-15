# SPA — Single Point of Authorization: one image with the Go server and the built web app.
#   docker build -t spa .
#   docker run -p 8080:8080 -e SPA_DATABASE_URL=… -e SPA_MASTER_KEY=… spa

# 1. The web app (React + Vite) → /src/web/dist
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# 2. The server → /out/spa (static, no cgo)
FROM golang:1.26-alpine AS server
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/spa ./cmd/spa

# 3. A minimal image: the binary, the web app, CA certificates, a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=server /out/spa /app/spa
COPY --from=web /src/web/dist /app/web
ENV SPA_WEB_DIR=/app/web \
    SPA_LISTEN=:8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/spa"]
