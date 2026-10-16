# SPA — Single Point of Authorization
#   make build   the web app and the server (backend/spa)
#   make test    Go tests (set SPA_TEST_POSTGRES for the database tests) and the web tests
#   make run     run SPA locally with the built web app (needs SPA_DATABASE_URL and SPA_MASTER_KEY)
#   make docker  build the image; make up / make down run it with PostgreSQL (docker compose)
#   make e2e-monitoring  end-to-end check with a real Umbrella Monitoring (docs/e2e.md)

GO      ?= go
NPM     ?= npm
IMAGE   ?= spa:latest
SPA_URL ?= http://localhost:8080

.PHONY: all build web server test test-go test-web run dev docker up down seed screenshots e2e-monitoring clean

all: build

build: web server

web/node_modules: web/package.json web/package-lock.json
	cd web && $(NPM) ci --no-audit --no-fund
	@touch web/node_modules

web: web/node_modules
	cd web && $(NPM) run build

server:
	cd backend && CGO_ENABLED=0 $(GO) build -trimpath -o spa ./cmd/spa

test: test-go test-web

test-go:
	cd backend && $(GO) vet ./... && $(GO) test ./...

test-web: web/node_modules
	cd web && $(NPM) test

run: build
	SPA_WEB_DIR=web/dist ./backend/spa

# The web app with hot reload on :5173; the API goes to SPA on :8080.
dev: web/node_modules
	cd web && $(NPM) run dev

docker:
	docker build -t $(IMAGE) .

up:
	docker compose up -d --build

down:
	docker compose down

# Demo data through the API of a running SPA (SPA_ADMIN_PASSWORD: the initial password of the first administrator).
seed:
	SPA_URL=$(SPA_URL) node scripts/seed-demo.mjs

# README screenshots of a running SPA on an empty database (Playwright with Chromium).
screenshots:
	SPA_URL=$(SPA_URL) node scripts/screenshots.mjs

# A live SPA and a real Umbrella Monitoring in Chromium: connect, roles, sign-in, synchronisation, disabling
# (docs/e2e.md; needs PostgreSQL, psql, Go, Node with Playwright and the Umbrella Monitoring repository).
e2e-monitoring: web
	node scripts/e2e-monitoring.mjs

clean:
	rm -rf web/dist backend/spa
