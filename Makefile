# Forge — Makefile minimal (tâches courantes : test, install, console, doctor).
# Sûreté d'abord : aucune cible ici ne tire quoi que ce soit contre une cible réelle.

.DEFAULT_GOAL := help
.PHONY: help test test-py test-rust test-pg check-version install console doctor clean demo demo-purple demo-seed

# --- Postgres (Stage 4) : conteneur éphémère pour les tests d'intégration du backend store-postgres ---
PG_IMAGE      ?= postgres:16
PG_CONTAINER  ?= forge-pg-test
PG_PORT       ?= 5433
PG_USER       ?= forge
PG_PASS       ?= forgepw
PG_DB         ?= forge
PG_URL        ?= postgres://$(PG_USER):$(PG_PASS)@localhost:$(PG_PORT)/$(PG_DB)

# --- Démo hors-ligne (engagement de référence synthétique — TLD .example, aucune cible réelle) ---
DEMO_DIR   ?= examples/reference-engagement
DEMO_DB    ?= forge-console-demo.db
PLUME_PORT ?= 8899

help:  ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

test: test-py test-rust  ## Suite complète (Python unittest + cargo test console)

test-py:  ## Tests Python (stdlib, zéro réseau)
	python3 -m unittest discover -s tests -t .

test-rust:  ## Tests Rust de la console (cargo test, offline)
	cd console && cargo test

test-pg:  ## Tests d'intégration Postgres (Stage 4) : spin docker PG -> cargo test --features store-postgres -> teardown
	@echo "[test-pg] démarrage d'un Postgres éphémère ($(PG_IMAGE)) sur :$(PG_PORT)..."
	@docker rm -f $(PG_CONTAINER) >/dev/null 2>&1 || true
	@docker run -d --name $(PG_CONTAINER) \
		-e POSTGRES_USER=$(PG_USER) -e POSTGRES_PASSWORD=$(PG_PASS) -e POSTGRES_DB=$(PG_DB) \
		-p $(PG_PORT):5432 $(PG_IMAGE) >/dev/null
	@echo "[test-pg] attente de la disponibilité..."
	@for i in $$(seq 1 30); do \
		docker exec $(PG_CONTAINER) pg_isready -U $(PG_USER) >/dev/null 2>&1 && break; \
		sleep 1; \
	done
	@echo "[test-pg] cargo test --features store-postgres (TEST_PG_URL positionné)..."
	@set -e; \
	  ( cd console && TEST_PG_URL="$(PG_URL)" cargo test --features store-postgres ); \
	  rc=$$?; \
	  echo "[test-pg] teardown du conteneur $(PG_CONTAINER)"; \
	  docker rm -f $(PG_CONTAINER) >/dev/null 2>&1 || true; \
	  exit $$rc

check-version:  ## Vérifie que VERSION == pyproject == Cargo.toml (échoue sinon)
	python3 scripts/check_version.py

install:  ## Installe forge en editable (met `forge` sur le PATH)
	pip install -e .

console:  ## Build release de la console puis la lance (127.0.0.1:7100)
	cd console && cargo build --release && ./target/release/forge-console

doctor:  ## Diagnostic des modules + outils/services attendus
	python3 -m forge.cli doctor

demo-seed:  ## Amorce la base démo avec l'engagement de référence (idempotent, offline)
	cd console && cargo build --release
	FORGE_CONSOLE_DB=$(DEMO_DB) console/target/release/forge-console seed-demo --dir $(DEMO_DIR)

demo: demo-seed  ## Console peuplée en 1 commande (Findings/Coverage/Runs) — http://127.0.0.1:7100
	@echo "[demo] console -> http://127.0.0.1:7100  (Findings/Coverage/Runs peuplés). Ctrl-C pour arrêter."
	@echo "[demo] pour l'onglet Purple (détecté/raté/MTTD) : make demo-purple"
	FORGE_CONSOLE_DB=$(DEMO_DB) FORGE_CONSOLE_SCOPE=$(DEMO_DIR)/scope.json FORGE_PKG_DIR=. \
		console/target/release/forge-console

demo-purple: demo-seed  ## Démo Purple : stub mock-Plume (DEMO, PAS un vrai SOC) + console -> matrice détecté/raté/MTTD
	@echo "[demo-purple] démarre le stub mock-Plume (DEMO FIXTURE — PAS un vrai SOC) sur 127.0.0.1:$(PLUME_PORT) puis la console."
	@echo "[demo-purple] onglet Purple -> http://127.0.0.1:7100 . Ctrl-C arrête la console ET le stub."
	@python3 tools/mock_plume.py --host 127.0.0.1 --port $(PLUME_PORT) --detections $(DEMO_DIR)/detections.jsonl & \
	  PLUME_PID=$$!; trap 'kill $$PLUME_PID 2>/dev/null' EXIT INT TERM; \
	  sleep 1; \
	  FORGE_CONSOLE_DB=$(DEMO_DB) FORGE_CONSOLE_SCOPE=$(DEMO_DIR)/scope.json FORGE_PKG_DIR=. \
	    PLUME_URL=http://127.0.0.1:$(PLUME_PORT) console/target/release/forge-console

clean:  ## Supprime les artefacts de build + la base démo (préserve scope/ledger gitignorés)
	rm -rf build dist *.egg-info .pytest_cache
	rm -f $(DEMO_DB) $(DEMO_DB)-wal $(DEMO_DB)-shm
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	cd console && cargo clean
