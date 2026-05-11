# Python checks (via uv)
UV ?= uv

.PHONY: check lint typecheck vuln test test-e2e

check: lint vuln test

lint:
	$(UV) run ruff check .

# Scope pip-audit to the project's resolved dependencies rather than the
# whole uv-managed environment — otherwise CVEs in `pip` itself (a uv
# transitive, not a project dep) block every commit.
vuln:
	$(UV) run pip-audit .

test:
	$(UV) run pytest --ignore=tests/e2e

test-e2e:
	$(UV) run pytest tests/e2e
