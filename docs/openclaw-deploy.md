# Déploiement OpenClaw (serveur distant)

## Cible

- OpenClaw actif en arrière-plan sur un serveur distant.
- Bind local uniquement (loopback) pour limiter la surface d'exposition.

## Étapes

1. Installer OpenClaw sur la machine distante.
2. Démarrer la gateway en service persistant (daemon système).
3. Configurer l'URL loopback utilisée par le wrapper (`ws://127.0.0.1:18789/gateway`).
4. Générer un token dédié pour le wrapper MCP.
5. Vérifier le healthcheck avant exposition via tunnel privé.

## Contrôles

- Aucun port public direct vers la gateway.
- Rotation du token périodique.
- Journalisation système active.
