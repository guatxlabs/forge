# Forge — Makefile minimal (tâches courantes : test, install, console, doctor).
# Sûreté d'abord : aucune cible ici ne tire quoi que ce soit contre une cible réelle.

.DEFAULT_GOAL := help
.PHONY: help test test-py test-rust install console doctor clean

help:  ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

test: test-py test-rust  ## Suite complète (Python unittest + cargo test console)

test-py:  ## Tests Python (stdlib, zéro réseau)
	python3 -m unittest discover -s tests -t .

test-rust:  ## Tests Rust de la console (cargo test, offline)
	cd console && cargo test

install:  ## Installe forge en editable (met `forge` sur le PATH)
	pip install -e .

console:  ## Build release de la console puis la lance (127.0.0.1:7100)
	cd console && cargo build --release && ./target/release/forge-console

doctor:  ## Diagnostic des modules + outils/services attendus
	python3 -m forge.cli doctor

clean:  ## Supprime les artefacts de build (préserve scope/ledger gitignorés)
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	cd console && cargo clean
