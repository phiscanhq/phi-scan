.DEFAULT_GOAL := help

DIFF_BASE ?= HEAD~1

.PHONY: install lint typecheck test scan clean help

install: ## Install dependencies and download spaCy model
	uv sync
	uv run python -m spacy download en_core_web_lg

lint: ## Run Ruff linter and formatter
	uv run ruff check . --fix
	uv run ruff format .

typecheck: ## Run mypy — zero errors required
	uv run mypy phi_scan/

test: ## Run pytest with coverage (fails below 80% — enforced in pyproject.toml)
	uv run pytest tests/

scan: ## Scan files changed since DIFF_BASE (default: HEAD~1)
	uv run phi-scan scan --diff "$(DIFF_BASE)"

clean: ## Remove cache and coverage artifacts
	find -P . -type d -name __pycache__ -exec rm -rf {} \;
	find -P . -type d -name .mypy_cache -exec rm -rf {} \;
	find -P . -type d -name .ruff_cache -exec rm -rf {} \;
	rm -rf .coverage htmlcov/ .pytest_cache/

help: ## List all available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
