.PHONY: test build docker-up docker-down package-lambda smoke

test:
	cd api && .venv/bin/pytest -q

build:
	cd web && npm run build

docker-up:
	docker compose up --build

docker-down:
	docker compose down

package-lambda:
	./scripts/package-lambda.sh

smoke:
	./scripts/smoke-test.sh
