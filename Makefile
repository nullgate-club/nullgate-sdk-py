PYTHON ?= 3.11

.PHONY: setup format check build

setup:
	uv sync --locked --python $(PYTHON) --group dev

format:
	uv run --locked --python $(PYTHON) ruff check --fix src/nullgate tests
	uv run --locked --python $(PYTHON) ruff format src/nullgate tests

check:
	uv run --locked --python $(PYTHON) ruff check src/nullgate tests
	uv run --locked --python $(PYTHON) ruff format --check src/nullgate tests
	uv run --locked --python $(PYTHON) mypy src/nullgate
	uv run --locked --python $(PYTHON) pytest

build:
	uv build --python $(PYTHON)
