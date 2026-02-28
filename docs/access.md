# Accès contrôlé

## Modèle retenu

- OpenClaw écoute en loopback sur le serveur.
- Les opérateurs accèdent via SSH tunnel ou réseau privé Tailscale.

## SSH tunnel (exemple)

- `ssh -N -L 18789:127.0.0.1:18789 user@remote-host`

## Bonnes pratiques

- Interdire l'ouverture publique du port 18789.
- Restreindre les clés SSH autorisées.
- Tracer les accès et limiter les comptes opérateurs.
