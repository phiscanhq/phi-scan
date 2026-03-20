.DEFAULT_GOAL := help

# HEAD~1 assumes full clone depth — shallow clones (e.g. actions/checkout default)
# must override: make scan DIFF_BASE=origin/main
# DIFF_BASE is trusted input — do not pass values from untrusted external sources
DIFF_BASE ?= HEAD~1

.PHONY: install lint format typecheck test scan clean help

install: ## Install dependencies and download spaCy model (hash-verified)
	uv sync
	uv pip install --require-hashes -r constraints/spacy-model.txt

lint: ## Check code style without modifying files (CI-safe)
	uv run ruff check . --no-fix
	uv run ruff format --check .

format: ## Apply Ruff auto-fixes and formatting
	uv run ruff check . --fix
	uv run ruff format .

typecheck: ## Run mypy — zero errors required
	uv run mypy phi_scan/

test: ## Run pytest with coverage (fails below 80% — enforced in pyproject.toml)
	uv run pytest tests/

scan: ## Scan files changed since DIFF_BASE (default: HEAD~1)
	@echo "$(DIFF_BASE)" | grep -qE '^[a-zA-Z0-9_.~^/:@-]+$$' \
		|| (echo "ERROR: DIFF_BASE contains invalid characters"; exit 1)
	uv run phi-scan scan --diff "$(DIFF_BASE)"

clean: ## Remove cache and coverage artifacts
	-find . -P -type d -name __pycache__ -prune -exec rm -rf --one-file-system {} \;
	-find . -P -type d -name .mypy_cache -prune -exec rm -rf --one-file-system {} \;
	-find . -P -type d -name .ruff_cache -prune -exec rm -rf --one-file-system {} \;
	-find . -P -maxdepth 1 -name .coverage ! -type l -exec rm -rf {} \;
	-find . -P -maxdepth 1 -name htmlcov ! -type l -exec rm -rf {} \;
	-find . -P -maxdepth 1 -name .pytest_cache ! -type l -exec rm -rf {} \;

help: ## List all available targets
	@# $$ below escapes $ in Make — the shell receives a single $ for awk field refs
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
