.PHONY: up down build test integration-test smoke logs clean fmt lint

up:
	docker compose up -d --build

down:
	docker compose down

build:
	go build ./cmd/secureshare

test:
	go test ./...

integration-test:
	INTEGRATION_TESTS=1 go test ./tests -count=1

smoke:
	./scripts/smoke-test.sh

logs:
	docker compose logs -f app

clean:
	docker compose down -v --remove-orphans
	rm -f secureshare

fmt:
	gofmt -w cmd internal tests

lint:
	go vet ./...
