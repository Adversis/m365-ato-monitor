.PHONY: help setup dev install deploy verify test test-install check lint lint-py lint-ps clean uninstall \
	docker-build docker-check docker-shell

# The local venv (make setup) if it exists, else the Python on PATH (the dev container).
PY := $(shell test -x function/.venv/bin/python && echo function/.venv/bin/python || echo python3)
DEV_IMAGE := m365-ato-monitor-dev
# Run the container as your own user ID, so that files it writes in this folder are yours.
DOCKER_RUN := docker run --rm --user "$$(id -u):$$(id -g)" -e HOME=/tmp -v "$(CURDIR)":/workspace -w /workspace

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Local development
# ---------------------------------------------------------------------------

setup: ## Set up local dev environment (Python 3.12 venv + deps + test deps)
	cd function && python3.12 -m venv .venv && \
	. .venv/bin/activate && \
	pip install -r requirements.txt -r ../tests/requirements-test.txt
	@echo ""
	@echo "Next steps:"
	@echo "  1. cp function/local.settings.json.example function/local.settings.json"
	@echo "  2. Fill in your Azure AD credentials in local.settings.json"
	@echo "  3. Run: make test  (offline, no Azure needed)"
	@echo "  4. Run: make dev   (requires Azure credentials)"

dev: ## Start the function locally (requires local.settings.json)
	@test -f function/local.settings.json || { echo "ERROR: function/local.settings.json not found. Run 'make setup' first."; exit 1; }
	cd function && . .venv/bin/activate && func start

# ---------------------------------------------------------------------------
# Azure (install.ps1: PowerShell 7.2+ and the Azure CLI)
# ---------------------------------------------------------------------------

install: ## Install or repair the monitor in Azure (asks questions)
	pwsh ./install.ps1

deploy: ## Deploy the code of this folder to the installed monitor
	pwsh ./install.ps1 -Update

verify: ## Show /api/status and run the detector self-test (ARGS=-SendTestAlerts also sends emails)
	pwsh ./install.ps1 -Verify $(ARGS)

# ---------------------------------------------------------------------------
# Testing & Linting
# ---------------------------------------------------------------------------

test: ## Run offline test suite (no Azure credentials needed)
	$(PY) -m pytest tests -q -p no:cacheprovider

test-install: ## Run the install.ps1 tests (Pester 5, fake Azure CLI)
	pwsh -NoProfile -Command "Import-Module Pester -MinimumVersion 5.0 -MaximumVersion 5.99.99; Invoke-Pester -Path tests/install.Tests.ps1 -Output Detailed -CI"

check: lint test test-install ## Run all linters and tests (what CI runs)

lint: lint-py lint-ps ## Run all linters

lint-py: ## Check Python and JavaScript syntax; pyflakes if installed
	@for f in function/*.py; do $(PY) -m py_compile "$$f" || exit 1; done
	@if $(PY) -m pyflakes --version >/dev/null 2>&1; then $(PY) -m pyflakes function tests; \
	else echo "pyflakes not installed: skipped (pip install -r tests/requirements-test.txt)"; fi
	@if command -v node >/dev/null 2>&1; then node --check function/ui/app.js; \
	else echo "node not installed: JavaScript check skipped"; fi
	@echo "Python syntax OK"

lint-ps: ## Check PowerShell syntax (needs pwsh)
	@if command -v pwsh >/dev/null 2>&1; then pwsh -NoProfile -File tests/Test-PowerShellSyntax.ps1; \
	else echo "pwsh not installed: PowerShell check skipped"; fi

# ---------------------------------------------------------------------------
# Dev container (Docker): the same Python, PowerShell, Pester, and Azure CLI
# versions for everyone. VS Code: "Reopen in Container" uses .devcontainer/.
# ---------------------------------------------------------------------------

docker-build: ## Build the dev container image
	docker build -f .devcontainer/Dockerfile -t $(DEV_IMAGE) .

docker-check: docker-build ## Run all linters and tests in the dev container
	$(DOCKER_RUN) $(DEV_IMAGE) make check

docker-shell: docker-build ## Open a shell in the dev container (this folder is /workspace)
	$(DOCKER_RUN) -it $(DEV_IMAGE) bash

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

clean: ## Remove local venv and caches
	rm -rf function/.venv function/__pycache__

uninstall: ## Delete the monitor from Azure (asks for confirmation)
	pwsh ./install.ps1 -Uninstall
