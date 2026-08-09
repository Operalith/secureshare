.PHONY: up down build test integration-test smoke security-test qa-test ui-time-test ui-navigation-test ui-e2e recipient-qa-test test-stack-up test-stack-down dev-reset-data openapi-validate logs clean fmt lint

up:
	docker compose up -d --build

down:
	docker compose down

build:
	go build ./cmd/secureshare

test:
	go test ./...

integration-test:
	./scripts/run-isolated-test.sh integration go test ./tests -count=1

smoke:
	./scripts/run-isolated-test.sh smoke ./scripts/smoke-test.sh

security-test:
	./scripts/run-isolated-test.sh security ./scripts/security-test.sh

qa-test:
	./scripts/run-isolated-test.sh qa ./scripts/qa-regression-test.sh

ui-time-test:
	node scripts/time-formatter-test.js

ui-navigation-test:
	node scripts/navigation-interaction-test.js

ui-e2e:
	./scripts/run-ui-e2e.sh

recipient-qa-test:
	RECIPIENT_QA_ONLY=1 ./scripts/run-ui-e2e.sh

test-stack-up:
	TEST_APP_PORT=18080 TEST_POSTGRES_PORT=15432 TEST_VAULT_PORT=18200 MAILPIT_SMTP_PORT=11025 MAILPIT_WEB_PORT=18025 docker compose -p secureshare_test --profile test up -d --build app-test mailpit

test-stack-down:
	docker compose -p secureshare_test --profile test down -v --remove-orphans

dev-reset-data:
	./scripts/dev-reset-data.sh

openapi-validate:
	ruby scripts/openapi-validate.rb

logs:
	docker compose logs -f app

clean:
	docker compose down -v --remove-orphans
	rm -f secureshare

fmt:
	gofmt -w cmd internal tests

lint:
	go vet ./...
