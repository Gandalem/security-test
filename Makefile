PYTHON ?= python

.PHONY: install up down create-indices seed analyze demo test clean

install:
	$(PYTHON) -m pip install -r requirements.txt

up:
	docker compose up -d

down:
	docker compose down

create-indices:
	$(PYTHON) scripts/create_indices.py

seed:
	$(PYTHON) scripts/seed_raw_logs.py

analyze:
	$(PYTHON) scripts/run_analyzer_once.py

demo: create-indices seed analyze
	$(PYTHON) scripts/generate_demo_report.py

test:
	$(PYTHON) -m pytest -q

clean:
	docker compose down -v
