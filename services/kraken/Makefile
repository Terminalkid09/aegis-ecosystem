.PHONY: help up down build logs shell test lint clean seed test-unit test-integration test-security monitoring-up monitoring-down backup restore

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

up: ## Start the full stack (app, sensors, db, redis)
	docker compose up -d --build

up-full: ## Start full stack with monitoring (Prometheus, Grafana, Alertmanager)
	docker compose -f docker-compose.yml up -d --build

down: ## Stop all services
	docker compose down

build: ## Build images only
	docker compose build

logs: ## Tail all logs
	docker compose logs -f

logs-app: ## Tail app logs only
	docker compose logs -f kraken_app

shell: ## Open a shell inside the app container
	docker exec -it kraken_app bash

test: ## Run all tests locally
	pytest -v --tb=short

test-unit: ## Run unit tests only
	pytest tests/unit/ -v --tb=short --cov=app --cov-report=term-missing

test-integration: ## Run integration tests (requires docker services)
	docker compose -f docker-compose.test.yml up -d
	sleep 10
	DATABASE_URL=postgresql+asyncpg://kraken_test:kraken_test_pass@localhost:5432/kraken_test_db \
	REDIS_URL=redis://:test_redis_pass@localhost:6379/0 \
	SECRET_KEY=test_secret_key_for_testing_only_32_chars_min \
	INTERNAL_API_KEY=test_internal_key_for_testing_only_32_chars \
	DEBUG=true \
	pytest tests/integration/ -v --tb=short
	docker compose -f docker-compose.test.yml down -v

test-security: ## Run security-focused tests
	pytest tests/unit/test_security.py -v --tb=short

test-cov: ## Run tests with HTML coverage report
	pytest --cov=app --cov-report=html:htmlcov
	@echo "Open htmlcov/index.html to view coverage"

lint: ## Lint with ruff
	ruff check app/ honeypot/ tests/

typecheck: ## Type check with mypy
	mypy app/ --ignore-missing-imports

migrate: ## Apply Alembic migrations
	docker exec -it kraken_app alembic upgrade head

migrate-new: ## Create a new Alembic migration (use: make migrate-new MSG="my change")
	docker exec -it kraken_app alembic revision --autogenerate -m "$(MSG)"

create-admin: ## Create admin user (use: make create-admin USER=admin PASS=yourpassword)
	docker exec -it kraken_app python scripts/create_admin.py $(USER) $(PASS)

seed: ## Seed demo data into the database
	docker exec -it kraken_app python scripts/seed_demo.py

monitoring-up: ## Start monitoring stack (Prometheus, Grafana, Alertmanager)
	docker compose -f docker-compose.yml up -d prometheus alertmanager grafana

monitoring-down: ## Stop monitoring stack
	docker compose -f docker-compose.yml stop prometheus alertmanager grafana

backup: ## Run backup manually
	docker exec -it kraken_backup /usr/local/bin/backup.sh

restore: ## Restore from backup (use: make restore DATE=20240115_120000 COMPONENT=all)
	docker exec -it kraken_backup /usr/local/bin/restore.sh $(DATE) $(COMPONENT)

clean: ## Remove containers, volumes and build cache
	docker compose down -v --remove-orphans
	docker system prune -f

health: ## Check health of all services
	docker compose ps
	@echo "--- App Health ---"
	@curl -sf http://localhost:8000/api/v1/health | jq . || echo "App not responding"
	@echo "--- Metrics ---"
	@curl -sf http://localhost:8000/metrics | head -20
