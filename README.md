# MCP OpenClaw Wrapper

Wrapper MCP Python pour exposer les artefacts `setup-vs-agent-firm` à OpenClaw via une intégration contrôlée.

## Objectif

- Exposer des tools MCP stables pour lister/charger les agents et prompts.
- Fournir un pont vers la Gateway OpenClaw WebSocket.
- Garder un mode d'accès privé et contrôlé (loopback + tunnel distant).

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
- `openclaw_health`: vérifie la connectivité Gateway.
- `openclaw_invoke`: envoie une requête contrôlée vers la Gateway OpenClaw.

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

## Sécurité

- Méthodes OpenClaw limitées par allowlist (`OPENCLAW_ALLOWED_METHODS`).
- Timeouts réseau définis (`OPENCLAW_TIMEOUT_SECONDS`).
- Possibilité de mode lecture seule (`READ_ONLY_MODE=true`).

Voir `docs/security.md` et `docs/access.md`.