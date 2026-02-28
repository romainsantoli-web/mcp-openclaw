# Sécurité du wrapper MCP

## Contrôles applicatifs

- Allowlist stricte des méthodes OpenClaw (`OPENCLAW_ALLOWED_METHODS`).
- Timeout de requêtes WS (`OPENCLAW_TIMEOUT_SECONDS`).
- Mode lecture seule (`READ_ONLY_MODE=true`) par défaut.

## Gestion des secrets

- Token OpenClaw uniquement via variables d'environnement.
- Ne jamais versionner `.env`.
- Rotation régulière des credentials.

## Risques couverts

- Réduction des appels arbitraires vers la gateway.
- Limitation des écritures mémoire non autorisées.
- Réduction du blast radius en cas de fuite d'un client MCP.
