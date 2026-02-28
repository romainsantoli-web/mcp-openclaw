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

4. Lancer le serveur MCP (stdio):

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

## Tools exposés

- `firm_list_departments`: liste les départements disponibles dans le repo source.
- `firm_load_agent`: charge le contenu d'un agent (`.agent.md`).
- `openclaw_health`: vérifie la connectivité Gateway.
- `openclaw_invoke`: envoie une requête contrôlée vers la Gateway OpenClaw.

## Sécurité

- Méthodes OpenClaw limitées par allowlist (`OPENCLAW_ALLOWED_METHODS`).
- Timeouts réseau définis (`OPENCLAW_TIMEOUT_SECONDS`).
- Possibilité de mode lecture seule (`READ_ONLY_MODE=true`).

Voir `docs/security.md` et `docs/access.md`.