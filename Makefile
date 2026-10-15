# SPA — Single Point of Authorization
#   make build   the web app and the server (backend/spa)
#   make test    Go tests (set SPA_TEST_POSTGRES for the database tests) and the web tests
#   make run     run SPA locally with the built web app (needs SPA_DATABASE_URL and SPA_MASTER_KEY)
#   make docker  build the image; make up / make down run it with PostgreSQL (docker compose)

GO      ?= go
NPM     ?= npm
IMAGE   ?= spa:latest
SPA_URL ?= http://localhost:8080

.PHONY: all build web server test test-go test-web run dev docker up down seed screenshots clean

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

clean:
	rm -rf web/dist backend/spa
