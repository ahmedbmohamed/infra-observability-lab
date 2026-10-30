# One command per step. "make all" builds the lab, configures it, tests it and runs the alert drill.
TF       ?= terraform
PYTHON   ?= python3
PROMTOOL ?= docker run --rm -v $(CURDIR):/w -w /w --entrypoint promtool prom/prometheus:v2.54.1

.PHONY: help all keys init up configure idempotence test drill waf-check waf-drill gotestwaf down lint

help:
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-12s %s\n", $$1, $$2}'

all: up configure idempotence test drill waf-drill ## Everything, from nothing to a tested lab

keys: .secrets/id_ed25519 ## Create the SSH key Ansible uses

.secrets/id_ed25519:
	mkdir -p .secrets && chmod 700 .secrets
	ssh-keygen -q -t ed25519 -N "" -C "infra-observability-lab" -f $@

init:
	$(TF) -chdir=terraform init -input=false

up: keys init ## Create the network, servers, Prometheus and Grafana
	$(TF) -chdir=terraform apply -input=false -auto-approve

configure: ## Configure the servers with Ansible
	cd ansible && ansible-playbook site.yml

idempotence: ## Second Ansible run: must change nothing
	cd ansible && ansible-playbook site.yml | tee ../.secrets/second-run.log
	@if grep -E 'changed=[1-9]' .secrets/second-run.log; then echo "Not idempotent: the second run changed something"; exit 1; fi
	@echo "Idempotent: the second run changed nothing"

test: ## Check HTTPS, SSH hardening, Prometheus and Grafana
	$(PYTHON) -m pytest -v tests

drill: ## Stop nginx on web1 and check that the alert fires then clears
	$(PYTHON) tests/alert_drill.py

waf-check: ## Send the attack and legitimate request corpus to the edge, print a table
	$(PYTHON) tests/waf_corpus.py

waf-drill: ## Simulate an attack campaign: WafAttackSpike must fire, legit users must not be blocked
	$(PYTHON) tests/waf_drill.py

gotestwaf: ## Independent WAF benchmark (GoTestWAF, needs Go): reports/gotestwaf.{json,html}
	tools/gotestwaf.sh

down: ## Destroy everything
	$(TF) -chdir=terraform destroy -input=false -auto-approve

lint: ## Static checks (no lab needed)
	$(TF) fmt -check -recursive terraform
	$(TF) -chdir=terraform init -backend=false -input=false >/dev/null
	$(TF) -chdir=terraform validate
	yamllint .
	cd ansible && ansible-lint
	$(PROMTOOL) check rules monitoring/alerts.yml
	$(PROMTOOL) test rules tests/alerts_test.yml
	$(TF) fmt -check -recursive cloudflare
	$(TF) -chdir=cloudflare init -backend=false -input=false >/dev/null
	$(TF) -chdir=cloudflare validate
