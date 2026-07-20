.PHONY: help install test demo run audit clean

help:
	@echo "Targets:"
	@echo "  install   Install runtime + dev dependencies (editable)"
	@echo "  test      Run the test suite"
	@echo "  demo      Run the end-to-end walking-skeleton flow on a sample alert"
	@echo "  run       Start the FastAPI dev server on :8000"
	@echo "  audit     Run the public-repository secret/PII audit"
	@echo "  clean     Remove caches and local run artifacts"

install:
	python3 -m pip install -e .[dev]

test:
	python3 -m pytest

demo:
	python3 -m app.demo

run:
	python3 -m uvicorn app.api.app:app --app-dir backend --reload --port 8000

audit:
	python3 scripts/public_repo_audit.py --history --fail-on high

clean:
	rm -rf .pytest_cache **/__pycache__ .local-audit runtime-data
