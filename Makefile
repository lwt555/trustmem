.PHONY: api attack bench test test-all test-v clean

api:
	python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload

attack:
	python -m scenarios.attacks

bench:
	python -m promptlens.bench

test:
	python -m pytest tests/ -q

test-v:
	python -m pytest tests/ -v

test-all:
	python -m pytest tests/ -v --tb=long

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
