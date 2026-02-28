# Runbook opérationnel

## Démarrage

1. Vérifier la gateway OpenClaw distante.
2. Ouvrir le tunnel privé si nécessaire.
3. Activer l'environnement virtuel Python.
4. Démarrer le wrapper MCP: `python -m src.main`.

## Vérifications

- `openclaw_health` doit retourner `ok=true`.
- `firm_list_departments` doit lister les départements détectés.

## Incident réseau

- Vérifier token et tunnel.
- Redémarrer le wrapper MCP.
- Contrôler les logs OpenClaw et service système.

## Mise à jour du repo source

- Re-synchroniser les agents sous `.github/agents`.
- Vérifier que les nouveaux départements sont bien détectés.
