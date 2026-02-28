# MCP OpenClaw Wrapper

Wrapper MCP Python pour exposer les artefacts `setup-vs-agent-firm` à OpenClaw via une intégration contrôlée.

## Objectif

- Exposer des tools MCP stables pour lister/charger les agents et prompts.
- Fournir un pont vers la Gateway OpenClaw WebSocket.
- Garder un mode d'accès privé et contrôlé (loopback + tunnel distant).

## État Git

- Dernier commit publié: `99ff1fd`
- Branche: `main`
- Remote: `origin/main`

## Prérequis

- Python 3.11+
- OpenClaw Gateway accessible (idéalement `127.0.0.1:18789` côté serveur)

## Démarrage rapide

1. Créer un environnement virtuel:

   - `python3 -m venv .venv`
   - `source .venv/bin/activate`

2. Installer les dépendances:

   - `pip install -r requirements.txt`

3. Configurer les variables:

   - `cp .env.example .env`

4. Lancer le serveur MCP:

   - `python -m src.main`

## Mode service (appel facile)

Scripts fournis:

- `scripts/start.sh`: démarre le service en arrière-plan.
- `scripts/stop.sh`: arrête le service.
- `scripts/status.sh`: affiche l'état et les derniers logs.

Exemple:

- `./scripts/start.sh`
- `./scripts/status.sh`
- `./scripts/stop.sh`
- `python scripts/smoke_test.py --url http://127.0.0.1:8011/mcp`

## Repo source setup-vs-agent-firm

- Par défaut, le wrapper utilise `external/setup-vs-agent-firm`.
- Tu peux forcer un chemin via `FIRM_REPO_PATH`.
- Sync manuel via tool `firm_repo_sync`.
- Sync auto au démarrage via `FIRM_REPO_AUTO_SYNC=true`.

## Tools exposés

- `firm_list_departments`: liste les départements disponibles dans le repo source.
- `firm_repo_status`: statut du repo source local.
- `firm_repo_sync`: clone/pull du repo source.
- `firm_list_agents`: liste tous les agents disponibles.
- `firm_list_prompts`: liste les prompts disponibles.
- `firm_load_agent`: charge le contenu d'un agent (`.agent.md`).
- `firm_load_prompt`: charge le contenu d'un prompt.
- `firm_validate_layout`: valide la structure attendue du repo source.
- `firm_run_delivery_workflow`: prépare un run CEO -> départements avec mémoire et dispatch OpenClaw optionnel.
- `firm_run_delivery_and_dispatch`: exécute workflow + dispatch OpenClaw avec un résumé compact.
- `routing_profiles_list`: liste les profils de modèles par famille de tâche.
- `routing_preview`: simule le choix de profil de modèle avant exécution.
- `routing_explain`: explique pourquoi un profil de modèle a été sélectionné.
- `routing_agent_plan`: génère le plan d'accès Copilot par agent/département.
- `openclaw_dispatch_diagnostics`: affiche la stratégie de dispatch active (mode, allowlist, endpoints).
- `enterprise_diagnostics`: affiche les diagnostics policy/audit/mémoire persistante.
- `observability_snapshot`: expose compteurs/latences runtime.
- `plugin_diagnostics`: expose l'état des plugins runtime et leur politique d'application.
- `cost_estimate`: estime le coût prévisionnel d'un workflow selon l'objectif/routing.
- `cost_status`: affiche les budgets actifs et la consommation journalière.
- `cost_recent`: retourne les enregistrements de coûts récents.
- `ops_recent_runs`: retourne l'historique récent des runs workflow.
- `ops_dashboard_snapshot`: agrège diagnostics enterprise + observabilité + coûts + plugins.
- `memory_context_preview`: affiche le contexte mémoire combiné (local + bridge API).
- `openclaw_health`: vérifie la connectivité Gateway.
- `openclaw_invoke`: envoie une requête contrôlée vers la Gateway OpenClaw.

## Architecture runtime complète

- Processus principal `python -m src.main`:
   - serveur MCP streamable HTTP (`MCP_HOST:MCP_PORT`, par défaut `127.0.0.1:8011`)
   - exporter Prometheus (`127.0.0.1:9108/metrics`)
   - Memory Bridge API (`127.0.0.1:9120/context/query`)
- Intégration OpenClaw:
   - voie WS (gateway)
   - fallback webhook selon politique `OPENCLAW_DISPATCH_MODE`
- Persistance:
   - audit JSONL
   - runtime workflow JSONL
   - coûts JSONL
   - mémoire via backend sélectionné

## Flux mémoire détaillé (contexte maximal)

1. Chaque action critique est journalisée (request + response):
   - `firm_repo_*`, `workflow`, `openclaw_*`, `memory_*`
2. Les événements sont écrits dans le backend mémoire actif.
3. Avec `memory_os_ai`, double persistance:
   - JSONL structuré (`MEMORY_OS_AI_EVENTS_PATH`)
   - miroir texte (`external/memory-os-ai/pdfs/mcp_openclaw_events/`)
4. Avant une exécution critique (`firm_run_delivery_workflow`, `openclaw_invoke`), le wrapper récupère le contexte via **2 canaux**:
   - source locale (`MemoryOsAiStore.retrieve_context`)
   - source API bridge (`POST /context/query`)
5. Les deux flux sont fusionnés + dédupliqués.
6. Le contexte fusionné est injecté dans les payloads pour guider la décision et l'exécution.

## Endpoints locaux

- MCP: `http://127.0.0.1:8011/mcp`
- Prometheus metrics: `http://127.0.0.1:9108/metrics`
- Prometheus health: `http://127.0.0.1:9108/healthz`
- Memory Bridge query: `http://127.0.0.1:9120/context/query`
- Memory Bridge health: `http://127.0.0.1:9120/healthz`

## Endpoint Prometheus (Phase 4)

- Un exporter Prometheus local est exposé par défaut sur `http://127.0.0.1:9108/metrics`.
- Le payload suit le format texte Prometheus (`version=0.0.4`) avec:
   - `mcp_openclaw_telemetry_enabled`
   - `mcp_openclaw_counter{name="..."}`
   - `mcp_openclaw_latency_count{name="..."}`
   - `mcp_openclaw_latency_avg_ms{name="..."}`
   - `mcp_openclaw_latency_max_ms{name="..."}`
- Health simple disponible sur `http://127.0.0.1:9108/healthz`.

Variables principales:

- `PROMETHEUS_EXPORTER_ENABLED`
- `PROMETHEUS_EXPORTER_HOST`
- `PROMETHEUS_EXPORTER_PORT`
- `PROMETHEUS_EXPORTER_PATH`

## Workflow orchestration (V2)

- Tool principal: `firm_run_delivery_workflow`.
- Paramètres clés:
   - `objective` (obligatoire)
   - `departments` (optionnel, sinon tous)
   - `prompt_name` (défaut: `firm-delivery.prompt.md`)
   - `memory_key` (défaut: `delivery/latest`)
   - `push_to_openclaw` (défaut: `false`)
   - `openclaw_method` (défaut: `agent.run`)
- Si `push_to_openclaw=true`, le payload est envoyé à la Gateway.
- Si `READ_ONLY_MODE=false`, un résumé du run est écrit en mémoire locale.
- Paramètres routing supportés:
   - `task_family` (`marketing|translation|debug|research`)
   - `quality_tier` (`high` recommandé)
   - `subtask_type` (ex: `hooks`, `long-form`, `calendar`, `localization`, `root-cause`, `synthesis`)
   - `latency_budget_ms` (optionnel)
   - `model_override` (optionnel)
- Paramètres runtime supportés sur les workflows:
   - `idempotency_key` (optionnel)
   - `max_attempts` (optionnel)

## Routage modèles (V2.4)

- Compatibilité Copilot via métadonnées de routage incluses dans le payload (`routing`, `copilot_hints`).
- Le routeur choisit un `model_profile` selon la famille de tâche et la qualité demandée.
- Le routeur peut raffiner le profil avec `subtask_type` pour des spécialisations plus précises.
- Profils par défaut:
   - `marketing` -> `creative-premium`
   - `translation` -> `translation-precision`
   - `debug` -> `reasoning-technical`
   - `research` -> `analysis-deep`
- Chaque agent reçoit désormais un plan `agent_copilot_access` dédié (profil, forces, guidance).
- Config env:
   - `ROUTING_MODE`
   - `ROUTING_DEFAULT_TASK_FAMILY`
   - `ROUTING_DEFAULT_QUALITY_TIER`
   - `ROUTING_DEFAULT_PROFILE`
   - `ROUTING_ALLOWED_PROFILES`
   - `ROUTING_ENABLE_COPILOT_HINTS`
   - `ROUTING_ENABLE_AGENT_COPILOT_ACCESS`

### Dispatch direct (V2.2)

- Tool: `firm_run_delivery_and_dispatch`.
- Comportement: force le dispatch OpenClaw (`agent.run` par défaut).
- Retour: statut compact (`dispatch_ok`, `openclaw_request_id`, résumé départements/prompt).
- Option `require_openclaw_success=true`: la tool retourne `ok=false` si l'envoi OpenClaw échoue.

## Robustesse dispatch (V2.3)

- Stratégie `OPENCLAW_DISPATCH_MODE`:
   - `auto`: essaie WS puis fallback webhook.
   - `ws_only`: WS uniquement.
   - `webhook_only`: webhook uniquement.
- Politique allowlist `OPENCLAW_ALLOWLIST_POLICY`:
   - `strict`: refuse localement les méthodes hors `OPENCLAW_ALLOWED_METHODS`.
   - `warn`: tente quand même et laisse OpenClaw décider.
- Webhook: configurable via `OPENCLAW_WEBHOOK_URL` (sinon dérivé automatiquement depuis `OPENCLAW_GATEWAY_URL`).
- Le dispatch tente plusieurs variantes de payload pour absorber les différences de schéma.
- Les retours incluent `attempts` pour diagnostiquer précisément chaque tentative.

## Enterprise Mode (Phase 1)

- `SECURE_PRODUCTION_MODE=true` active des contrôles policy supplémentaires.
- `PolicyEngine` contrôle les catégories `read|write|network` par tool.
- `AuditLogger` écrit une trace JSONL des actions critiques.
- `MEMORY_BACKEND=sqlite` active une mémoire persistante sur disque.
- Diagnostic global via `enterprise_diagnostics`.

Variables principales:

- `POLICY_BLOCKED_TOOLS`
- `POLICY_ALLOW_WRITE_TOOLS`
- `POLICY_ALLOW_NETWORK_TOOLS`
- `AUDIT_ENABLED`
- `AUDIT_FILE_PATH`
- `MEMORY_BACKEND`
- `MEMORY_SQLITE_PATH`

## Enterprise Mode (Phase 2)

- Runtime workflow avec retries et idempotence.
- Historique des runs persistant (`workflow_runs.jsonl`).
- Télémétrie interne (compteurs + latences).

Variables principales:

- `TELEMETRY_ENABLED`
- `WORKFLOW_MAX_ATTEMPTS`
- `WORKFLOW_IDEMPOTENCY_ENABLED`
- `WORKFLOW_STORE_PATH`

## Enterprise Mode (Phase 3)

- Plugins runtime pré/post workflow (normalisation + garde-fous objectifs).
- Cost guard avec budgets par run et journalier.
- Snapshot ops consolidé pour pilotage rapide.

Variables principales:

- `PLUGINS_ENABLED`
- `PLUGIN_ENFORCE_OBJECTIVE_MIN_LENGTH`
- `PLUGIN_POLICY_MODE`
- `COST_GUARD_ENABLED`
- `COST_GUARD_POLICY_MODE`
- `COST_GUARD_PER_RUN_BUDGET`
- `COST_GUARD_DAILY_BUDGET`
- `COST_GUARD_LEDGER_PATH`

## Mémoire unifiée Memory OS AI

- Backend mémoire recommandé: `MEMORY_BACKEND=memory_os_ai`.
- Le wrapper journalise les actions (requêtes + résultats) dans le moteur mémoire:
   - `actions/all`
   - `actions/<tool>`
   - `actions/<kind>` (`read|write|network|execution|workflow`)
- Les événements sont persistés dans:
   - `MEMORY_OS_AI_EVENTS_PATH` (JSONL)
   - `external/memory-os-ai/pdfs/mcp_openclaw_events/` (miroir texte ingérable par Memory OS AI)
- Avant les exécutions critiques (`workflow`, `openclaw_invoke`), le wrapper récupère un contexte mémoire global et l'injecte dans le payload pour améliorer la pertinence.
- Le contexte global utilise désormais **2 sources en parallèle**:
   - source locale (`memory_os_ai_store`)
   - source passerelle API Memory Bridge (`/context/query`)
- Le résultat est fusionné et dédupliqué avant injection pour donner un contexte maximal.

Variables principales:

- `MEMORY_BACKEND`
- `MEMORY_OS_AI_REPO_PATH`
- `MEMORY_OS_AI_EVENTS_PATH`
- `MEMORY_OS_AI_CONTEXT_LIMIT`

### Memory Bridge API (contexte enrichi)

- Service local démarré avec le serveur MCP.
- Endpoint query: `POST http://127.0.0.1:9120/context/query`
- Endpoint health: `GET http://127.0.0.1:9120/healthz`
- Tool MCP de debug: `memory_context_preview`

Variables principales:

- `MEMORY_BRIDGE_ENABLED`
- `MEMORY_BRIDGE_HOST`
- `MEMORY_BRIDGE_PORT`
- `MEMORY_BRIDGE_QUERY_PATH`
- `MEMORY_BRIDGE_TIMEOUT_SECONDS`
- `MEMORY_BRIDGE_USE_IN_CONTEXT`

## Vérification rapide (runbook)

- Démarrer:
   - `./scripts/start.sh`
- Vérifier statut:
   - `./scripts/status.sh`
- Smoke complet:
   - `python scripts/smoke_test.py`
- Vérifier bridge mémoire:
   - `curl -s http://127.0.0.1:9120/healthz`
- Vérifier metrics:
   - `curl -s http://127.0.0.1:9108/metrics | head`

## Sécurité

- Méthodes OpenClaw limitées par allowlist (`OPENCLAW_ALLOWED_METHODS`).
- Timeouts réseau définis (`OPENCLAW_TIMEOUT_SECONDS`).
- Possibilité de mode lecture seule (`READ_ONLY_MODE=true`).

Voir `docs/security.md` et `docs/access.md`.

## SDK Python léger (Phase 4)

- Client async inclus: [src/sdk_client.py](src/sdk_client.py)
- Classe: `McpOpenClawClient`
- Usage rapide:

   - `from src.sdk_client import McpOpenClawClient`
   - `async with McpOpenClawClient("http://127.0.0.1:8011/mcp") as client:`
   - `tools = await client.list_tools()`
   - `snapshot = await client.dashboard_snapshot(limit=5)`