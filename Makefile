.PHONY: install dev lint typecheck test test-all integration loadtest loadtest-smoke image-quantum demo-images demo-up demo-reload demo-reset demo-down image demo serve

PY ?= python3

install:
	$(PY) -m pip install .

dev:
	$(PY) -m pip install -e ".[dev,agent,quantum]"

lint:
	ruff check src tests
	ruff format --check src tests

typecheck:
	$(PY) -m mypy

test:
	$(PY) -m pytest

integration:
	$(PY) -m pytest -m integration

test-all: lint typecheck test integration

demo-images:
	docker compose -f demo/docker-compose.yml build

demo-up:
	$(PY) demo/setup.py
	docker compose -f demo/docker-compose.yml up -d --build

demo-reload:
	for c in app-modern app-legacy app-tls12 app-ready app-plain; do docker exec aegisq-$$c nginx -s reload; done

demo-reset:
	$(PY) demo/setup.py --configs-only
	$(MAKE) demo-reload

demo-down:
	docker compose -f demo/docker-compose.yml down

image:
	docker build -t aegisq:latest .

# Image with Qiskit preinstalled (saves the slow Qiskit install on every new machine).
image-quantum:
	docker build --build-arg EXTRAS=agent,quantum -t aegisq:quantum .

# The 3-minute demo, scripted: scan, CBOM, risk, then the agent (approve on the dashboard).
demo: demo-reset
	aegisq scan demo/fleet.yaml
	aegisq cbom --out cbom.json
	aegisq risk --sweep 5,10,15,20
	aegisq migrate demo/fleet.yaml --approve-in terminal

serve:
	aegisq serve --inventory demo/fleet.yaml

# k6 load tests (local k6 or the grafana/k6 image). The tls scenario needs `make demo-up`.
loadtest:
	loadtest/run.sh

loadtest-smoke:
	SMOKE=1 loadtest/run.sh
