.PHONY: help install lint test demo run audit clean

# Everything runs from a project virtual environment, so `make install` works on
# systems whose Python refuses global installs (PEP 668).
PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

help:
	@echo "Targets:"
	@echo "  install   Create $(VENV) and install runtime + dev dependencies (editable)"
	@echo "  lint      Run ruff (correctness rules)"
	@echo "  test      Run the test suite"
	@echo "  demo      Run the end-to-end walking-skeleton flow on the sample alerts"
	@echo "  run       Start the FastAPI dev server on :8000"
	@echo "  audit     Run the public-repository secret/PII audit"
	@echo "  clean     Remove generated Python/pytest caches; preserve private records and runtime data"

install:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install -q -e .[dev]

lint:
	$(BIN)/python -m ruff check .

test:
	$(BIN)/python -m pytest

demo:
	$(BIN)/python -m app.demo

run:
	$(BIN)/python -m uvicorn app.api.app:app --app-dir backend --reload --port 8000

audit:
	$(PYTHON) scripts/public_repo_audit.py --history --fail-on high

clean:
	rm -rf -- .pytest_cache
	find backend scripts -type d -name __pycache__ -prune -exec rm -rf -- {} +
