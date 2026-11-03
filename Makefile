# ==============================================================================
# SUTRAM Platform Makefile
# Cross-platform development and testing automation
# ==============================================================================

.PHONY: help setup dev dev-backend dev-frontend test lint format eval samples clean check-env

PYTHON ?= python
UV ?= uv
NPM ?= npm

help:
	@echo "========================================================================"
	@echo " SUTRAM: AI-Powered Multimedia Forensics Platform"
	@echo "========================================================================"
	@echo "Available commands:"
	@echo "  make setup        : Install backend dependencies (uv) & frontend (npm)"
	@echo "  make dev          : Run both backend and frontend development servers"
	@echo "  make dev-backend  : Start FastAPI backend server on port 8000"
	@echo "  make dev-frontend : Start Vite frontend server on port 5173"
	@echo "  make test         : Run pytest test suite"
	@echo "  make lint         : Run ruff check and mypy type checks"
	@echo "  make format       : Format Python code with ruff format"
	@echo "  make eval         : Run detector evaluation benchmarks"
	@echo "  make samples      : Generate synthetic/tampered sample test media"
	@echo "  make clean        : Remove caches, temp working copies and build artifacts"
	@echo "========================================================================"

setup:
	@echo "==> Setting up SUTRAM environment..."
	@if [ ! -f .env ]; then cp .env.example .env; echo "Created .env from .env.example"; fi
	@mkdir -p evidence_store/originals evidence_store/working evidence_store/artifacts evidence_store/reports models_cache
	@echo "==> Installing backend dependencies with uv..."
	uv pip install -e "backend[dev]"
	@echo "==> Installing frontend dependencies with npm..."
	cd frontend && npm install
	@echo "==> Setup completed successfully."

dev-backend:
	@echo "==> Starting SUTRAM FastAPI Backend on http://localhost:8000..."
	uv run uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

dev-frontend:
	@echo "==> Starting SUTRAM React/Vite Frontend on http://localhost:5173..."
	cd frontend && npm run dev

dev:
	@echo "==> Starting SUTRAM Full-Stack Development Environment..."
	@echo "Tip: For separate terminal tabs, run 'make dev-backend' and 'make dev-frontend'"
	docker-compose up

test:
	@echo "==> Running backend test suite with pytest..."
	uv run pytest backend/tests -v --durations=10

lint:
	@echo "==> Running ruff check on backend codebase..."
	uv run ruff check backend
	@echo "==> Running mypy type checking..."
	uv run mypy backend/app
	@echo "==> Checking frontend TypeScript compilation..."
	cd frontend && npm run typecheck

format:
	@echo "==> Formatting backend code with ruff..."
	uv run ruff format backend
	uv run ruff check --fix backend

eval:
	@echo "==> Running forensic detector evaluation suite..."
	uv run python backend/evaluation/eval.py --samples-dir samples --output-dir docs/eval_results

samples:
	@echo "==> Generating license-clear forensic test media samples..."
	uv run python scripts/make_samples.py --output samples

clean:
	@echo "==> Cleaning cache and temporary files..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	rm -rf evidence_store/working/* evidence_store/artifacts/*
