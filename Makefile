.PHONY: install run test lint format docker migrate clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	python -m venv venv
	. venv/bin/activate && pip install -r requirements/dev.txt

run: ## Start development server
	FLASK_CONFIG=development flask run --reload

test: ## Run tests with coverage
	python -m pytest tests/ --cov=app --cov-report=term-missing --cov-report=html

lint: ## Run all linters
	black --check app/ tests/
	isort --check-only app/ tests/
	pylint app/

format: ## Auto-format code
	black app/ tests/
	isort app/ tests/

typecheck: ## Run mypy type checking
	mypy app/

security: ## Run security scan
	bandit -r app/ -q

docker: ## Build and start all services
	docker-compose up --build -d

docker-down: ## Stop all services
	docker-compose down

migrate: ## Run database migrations
	flask db upgrade

seed: ## Seed admin user
	flask seed-admin

clean: ## Remove build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache htmlcov .coverage .mypy_cache
