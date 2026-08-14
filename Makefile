.PHONY: api attack bench test test-all test-v contract rules crypto figures web demo clean

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

contract:
	python tools/contract_check.py

rules:
	python tools/gen_trust_rules.py

crypto:
	python -m pytest tests/test_abe.py tests/test_abe_isolation.py tests/test_crypto.py tests/test_decrypt_ledger.py tests/test_signing.py -q

figures:
	python scripts/generate_figures.py

web:
	python -m webbrowser "http://localhost:8000/"

demo:
	python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
