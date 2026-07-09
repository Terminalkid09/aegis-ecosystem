.PHONY: help up down build logs shell test lint clean migrate migrate-new seed test-unit test-integration test-security

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

up: ## Start aegis-brain with dependencies
	docker compose -f ../../docker-compose.yml up -d aegis-postgres aegis-redis aegis-ollama aegis-brain

up-full: ## Start full Aegis ecosystem
	docker compose -f ../../docker-compose.yml up -d

down: ## Stop all services
	docker compose -f ../../docker-compose.yml down

build: ## Build images only
	docker compose -f ../../docker-compose.yml build aegis-brain

logs: ## Tail brain logs
	docker compose -f ../../docker-compose.yml logs -f aegis-brain

shell: ## Open a shell inside the brain container
	docker exec -it aegis-brain bash

test: ## Run all tests locally
	pytest -v --tb=short

test-unit: ## Run unit tests only
	pytest tests/ -v --tb=short -k "not integration" --cov=app --cov-report=term-missing

test-integration: ## Run integration tests (requires docker services)
	docker compose -f docker-compose.test.yml up -d
	sleep 15
	DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/aegis_test \
	REDIS_URL=redis://:test_redis_pass@localhost:6379 \
	REDIS_PASSWORD=test_redis_pass \
	JWT_SECRET=test_jwt_secret_for_testing_only_32_chars_minimum_length \
	AGENT_ENROLL_KEY=test_enrollment_token_16_chars_min \
	MASTER_KEY_B64=Q/wCZ5reU82bQpZppUc6Qq80sybBPz4Q276NbMBF97Q= \
	OLLAMA_URL=http://localhost:11434/api/generate \
	DEBUG=true \
	ALLOWED_ORIGINS=http://localhost:3000 \
	pytest tests/integration/ -v --tb=short
	docker compose -f docker-compose.test.yml down -v

test-security: ## Run security-focused tests
	pytest tests/ -v --tb=short -k "security or auth"

test-cov: ## Run tests with HTML coverage report
	pytest --cov=app --cov-report=html:htmlcov
	@echo "Open htmlcov/index.html to view coverage"

lint: ## Lint with ruff
	ruff check app/ tests/

typecheck: ## Type check with mypy
	mypy app/ --ignore-missing-imports

migrate: ## Apply Alembic migrations
	docker exec -it aegis-brain alembic upgrade head

migrate-new: ## Create a new Alembic migration (use: make migrate-new MSG="my change")
	docker exec -it aegis-brain alembic revision --autogenerate -m "$(MSG)"

seed: ## Seed demo data
	docker exec -it aegis-brain python scripts/check_test_db.py

health: ## Check health of all services
	docker compose -f ../../docker-compose.yml ps
	@echo "--- Brain Health ---"
	@curl -sf http://localhost:8000/health/live | jq . || echo "Brain not responding"
	@echo "--- Readiness ---"
	@curl -sf http://localhost:8000/health/ready | jq . || echo "Not ready"
	@echo "--- Circuit Breakers ---"
	@curl -sf http://localhost:8000/health/circuit-breakers | jq .

clean: ## Remove containers, volumes and build cache
	docker compose -f ../../docker-compose.yml down -v --remove-orphans
	docker system prune -f