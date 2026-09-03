.PHONY: unit e2e ci clean

# Unit tests (no Docker required)
unit:
	pytest -m "not e2e"

# Full end-to-end audit against a dockerized vulnerable WordPress (Docker required)
e2e:
	bash scripts/run_ci_locally.sh --e2e-only

# The whole pipeline, exactly as CI runs it
ci:
	bash scripts/run_ci_locally.sh

clean:
	rm -rf ci/run .pytest_cache .coverage htmlcov __pycache__