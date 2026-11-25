PYTHON ?= 3.11

.PHONY: setup format check build

setup:
	uv sync --locked --python $(PYTHON) --all-extras --group dev

format:
	uv run --locked --python $(PYTHON) --all-extras ruff check --fix src/nullgate tests examples
	uv run --locked --python $(PYTHON) --all-extras ruff format src/nullgate tests examples

check:
	uv run --locked --python $(PYTHON) --all-extras ruff check src/nullgate tests examples
	uv run --locked --python $(PYTHON) --all-extras ruff format --check src/nullgate tests examples
	uv run --locked --python $(PYTHON) --all-extras mypy src/nullgate tests/typing/valid.py examples
	uv run --locked --python $(PYTHON) --all-extras pytest

build:
	uv build --python $(PYTHON)
