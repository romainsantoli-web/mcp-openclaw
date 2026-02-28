# CLAUDE.md — mcp-openclaw-extensions

> Lu automatiquement par Claude Code à chaque session.
> Règles non-négociables + pratiques Anthropic à appliquer sur **chaque tâche**.

---

## ⚠️ RÈGLES OBLIGATOIRES — TOUTES LES TÂCHES

### 1. Git propre avant de commencer
```bash
git status
git checkout -b feat/<slug>
```
Commiter des checkpoints toutes les 30-50 lignes. Ne jamais travailler sur `main`.

### 2. Pydantic sur tous les nouveaux tools
- Nouveau tool MCP → classe `BaseModel` dans `src/models.py` + entrée dans `TOOL_MODELS`
- Contraintes obligatoires : `min_length`, `max_length`, regex, blocage `..` sur les chemins

### 3. Tests — 100 % avant chaque push
```bash
source .venv/bin/activate
python -m pytest tests/ -v        # doit être 100 % pass
```
- 1 test positif + 1 test négatif (input invalide) par nouveau tool ou fonction

### 4. Secrets masqués
- Aucun token dans les logs ni les commits
- Utiliser `_mask_secret(val)` pour tout affichage de credentials
- `.env` toujours dans `.gitignore`

### 5. Outputs AI marqués
```
⚠️ Contenu généré par IA — validation humaine requise.
```

---

## 🏗️ ARCHITECTURE DU SERVEUR MCP

```
mcp-openclaw-extensions/
├── CLAUDE.md                  ← ce fichier
├── src/
│   ├── main.py                ← aiohttp MCP server, port 8012
│   ├── models.py              ← 16 Pydantic BaseModel (validation des inputs)
│   ├── vs_bridge.py           ← 4 tools VS Code ↔ OpenClaw Gateway
│   ├── gateway_fleet.py       ← 6 tools fleet manager multi-instances
│   └── delivery_export.py     ← 6 tools pipeline deliverables
├── tests/
│   └── test_smoke.py          ← 15 tests (9 smoke + 6 Pydantic)
└── scripts/
    ├── start.sh / stop.sh / status.sh
```

**Total : 16 tools MCP, 15 tests passants, validation Pydantic sur 100 % des inputs.**

---

## 🔧 DÉVELOPPEMENT LOCAL

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Démarrer le serveur
bash scripts/start.sh
bash scripts/status.sh    # vérifier : 16 tools, HTTP OK

# Tests
python -m pytest tests/ -v

# Arrêter
bash scripts/stop.sh
```

Variables d'environnement : copier `.env.example` → `.env` et remplir les tokens.

---

## 📐 AJOUTER UN NOUVEAU TOOL — PROCÉDURE OBLIGATOIRE

1. **Handler** dans le module approprié (`vs_bridge.py`, `gateway_fleet.py`, ou `delivery_export.py`)
   ```python
   async def mon_nouveau_tool(param1: str, param2: int = 0) -> dict[str, Any]:
       ...
   ```

2. **Entrée dans `TOOLS`** du module (inputSchema JSON Schema)

3. **Modèle Pydantic** dans `src/models.py`
   ```python
   class MonNouveauToolInput(BaseModel):
       param1: Annotated[str, Field(min_length=1, max_length=512)]
       param2: int = Field(default=0, ge=0, le=1000)
   ```

4. **Enregistrement** dans `TOOL_MODELS` à la fin de `models.py`

5. **Tests** dans `tests/test_smoke.py` :
   - 1 test cas valide (résultat attendu)
   - 1 test input invalide (Pydantic doit rejeter)

6. **Vérifier** : `pytest -v` → 100 % pass → `git commit` → `git push`

---

## 🔌 PROTOCOLE MCP (référence rapide)

```
POST http://127.0.0.1:8012/mcp
Content-Type: application/json

{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
 "params": {"name": "firm_export_document", "arguments": {...}}}
```

Méthodes supportées : `initialize`, `tools/list`, `tools/call`, `ping`

Réponse erreur Pydantic :
```json
{"isError": true, "content": [{"type": "text", "text":
  "{\"error\": \"Validation failed\", \"details\": [{\"loc\": [\"field\"], \"msg\": \"...\"}]}"}]}
```

---

## 🏢 WORKFLOWS ANTHROPIC — BONNES PRATIQUES

### Prototypage rapide (auto-accept)
- `shift+tab` en mode auto-accept pour les tâches ≤ 2h
- Claude écrit → tests tournent → Claude corrige → cycle
- Toujours partir d'un état git propre

### Débogage par stack trace
- Fournir la stack trace complète en contexte
- Tracer le flux de contrôle avant de proposer un fix
- Fournir les commandes exactes, pas seulement le diagnostic

### Instances parallèles
- Plusieurs instances sur des modules différents simultanément
- Chaque instance garde son contexte — pas de perte
- Utiliser `firm_gateway_fleet_broadcast` pour synchroniser

### Documentation de fin de session
Après chaque session significative :
1. Résumer ce qui a été accompli
2. Lister les décisions d'architecture
3. Mettre à jour ce `CLAUDE.md` si nouvelle pratique découverte
4. Commiter : `docs: update CLAUDE.md — <session summary>`

---

## 📋 CHECKLIST AVANT CHAQUE PUSH

- [ ] Branche git dédiée (pas `main`)
- [ ] Pydantic : modèle créé/mis à jour pour chaque nouveau tool
- [ ] `pytest -v` → 100 % pass
- [ ] Aucun secret dans `git diff --cached`
- [ ] Commit message : `type(scope): description`
- [ ] `CLAUDE.md` mis à jour si nouvelle pratique

---

## 🔑 PHILOSOPHIE

> "Plus les fichiers CLAUDE.md sont détaillés, plus Claude Code performe bien."
> C'est le levier d'optimisation n°1. — Anthropic, *How Anthropic teams use Claude Code*

Le rôle humain = **supervision + review + architecture**. Délègue le bas niveau.
