SHELL := /bin/bash
.PHONY: install-dev test test-delegation-workflow test-delegation-workflow-did-web

# Target to install development dependencies
install-dev:
	@echo "Installing development dependencies using uv..."
	uv pip install .[dev]
	@echo "Development dependencies installed."

test:
	uv run pytest

test-delegation-workflow:
	./test_delegation_workflow.sh

test-delegation-workflow-did-web:
	./test_delegation_workflow_did_web.sh

