"""
supplier_management.py — Procurement & Supplier Management tools

Implements 5 tools for the Suppliers department:
  - Supplier sourcing (market search, identification, shortlisting)
  - Supplier evaluation (multi-criteria scoring)
  - TCO analysis (total cost of ownership over 3-5 years)
  - Contract clause analysis (SLA, penalties, reversibility)
  - Supplier risk monitoring (continuous tracking)

Tools exposed (5):
  openclaw_supplier_search            — market-wide supplier sourcing
  openclaw_supplier_evaluate          — multi-criteria supplier evaluation
  openclaw_supplier_tco_analyze       — total cost of ownership analysis
  openclaw_supplier_contract_check    — contract clause analysis
  openclaw_supplier_risk_monitor      — supplier risk monitoring CRUD
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_SUPPLIER_CATEGORIES: dict[str, dict[str, Any]] = {
    "saas": {"label": "SaaS / Software", "sources": ["G2", "Capterra", "Product Hunt", "StackShare"]},
    "cloud": {"label": "Cloud / Infrastructure", "sources": ["Gartner", "Forrester", "CloudCompare"]},
    "services": {"label": "Services professionnels", "sources": ["Malt", "Upwork", "Kompass", "LinkedIn"]},
    "hardware": {"label": "Matériel / Hardware", "sources": ["LDLC Pro", "Dell", "Lenovo", "Insight"]},
    "office": {"label": "Fournitures bureau", "sources": ["Bruneau", "JPG", "Amazon Business"]},
    "logistics": {"label": "Logistique / Transport", "sources": ["Upela", "Boxtal", "DHL", "Chronopost"]},
    "raw_materials": {"label": "Matières premières", "sources": ["Alibaba", "GlobalSources", "Kompass", "Europages"]},
    "marketing": {"label": "Marketing / Agence", "sources": ["Sortlist", "Malt", "Clutch", "GoodFirms"]},
    "consulting": {"label": "Conseil / Audit", "sources": ["Consultport", "Comatch", "LinkedIn"]},
    "telecom": {"label": "Télécom / Internet", "sources": ["Ariase Pro", "comparateurs FAI"]},
    "insurance": {"label": "Assurance", "sources": ["Alan", "Hiscox", "AXA Pro", "LeLynx Pro"]},
    "accounting": {"label": "Comptabilité / Expert-comptable", "sources": ["Comptacom", "Indy", "Pennylane"]},
}

_EVALUATION_CRITERIA = [
    {"criterion": "quality", "label": "Qualité produit/service", "default_weight": 20},
    {"criterion": "price", "label": "Prix / Rapport qualité-prix", "default_weight": 20},
    {"criterion": "delivery", "label": "Délai de livraison", "default_weight": 10},
    {"criterion": "support", "label": "Support / SAV", "default_weight": 10},
    {"criterion": "reliability", "label": "Fiabilité / Disponibilité", "default_weight": 10},
    {"criterion": "scalability", "label": "Capacité de montée en charge", "default_weight": 5},
    {"criterion": "security", "label": "Sécurité / RGPD", "default_weight": 10},
    {"criterion": "financial_health", "label": "Solidité financière", "default_weight": 5},
    {"criterion": "references", "label": "Références clients", "default_weight": 3},
    {"criterion": "certifications", "label": "Certifications (ISO, etc.)", "default_weight": 3},
    {"criterion": "innovation", "label": "Innovation / R&D", "default_weight": 2},
    {"criterion": "sustainability", "label": "RSE / Développement durable", "default_weight": 2},
    {"criterion": "contract_flexibility", "label": "Flexibilité contractuelle", "default_weight": 5},
    {"criterion": "integration", "label": "Facilité d'intégration", "default_weight": 3},
    {"criterion": "reversibility", "label": "Réversibilité / Portabilité", "default_weight": 2},
]

_CONTRACT_CLAUSES = [
    {"clause": "sla_availability", "label": "SLA de disponibilité", "priority": "CRITICAL", "description": "Engagement de disponibilité (99.9%, 99.95%, etc.)"},
    {"clause": "sla_response_time", "label": "SLA temps de réponse", "priority": "CRITICAL", "description": "Temps de réponse garanti (support, incidents)"},
    {"clause": "penalties", "label": "Pénalités de retard/indisponibilité", "priority": "HIGH", "description": "Compensations financières en cas de non-respect SLA"},
    {"clause": "data_protection", "label": "Protection des données (DPA)", "priority": "CRITICAL", "description": "RGPD Data Processing Agreement"},
    {"clause": "reversibility", "label": "Clause de réversibilité", "priority": "HIGH", "description": "Plan de migration et export des données en sortie"},
    {"clause": "ip_ownership", "label": "Propriété intellectuelle", "priority": "HIGH", "description": "Propriété des développements spécifiques"},
    {"clause": "confidentiality", "label": "NDA / Confidentialité", "priority": "HIGH", "description": "Protection des informations échangées"},
    {"clause": "liability_cap", "label": "Plafond de responsabilité", "priority": "MEDIUM", "description": "Limite de l'indemnisation en cas de dommage"},
    {"clause": "termination", "label": "Résiliation", "priority": "HIGH", "description": "Conditions et préavis de résiliation"},
    {"clause": "price_revision", "label": "Révision tarifaire", "priority": "MEDIUM", "description": "Mécanisme d'indexation ou de révision des prix"},
    {"clause": "force_majeure", "label": "Force majeure", "priority": "MEDIUM", "description": "Gestion des événements exceptionnels"},
    {"clause": "audit_right", "label": "Droit d'audit", "priority": "MEDIUM", "description": "Possibilité d'auditer le fournisseur (sécurité, conformité)"},
    {"clause": "subcontracting", "label": "Sous-traitance", "priority": "MEDIUM", "description": "Encadrement de la sous-traitance par le fournisseur"},
    {"clause": "jurisdiction", "label": "Loi applicable / Juridiction", "priority": "LOW", "description": "Choix du droit applicable et du tribunal compétent"},
]

_RISK_CATEGORIES = {
    "financial": {"label": "Risque financier", "description": "Solidité financière, trésorerie, dettes"},
    "dependency": {"label": "Risque de dépendance", "description": "Concentration sur un seul fournisseur"},
    "geopolitical": {"label": "Risque géopolitique", "description": "Instabilité pays, sanctions, guerre commerciale"},
    "service_level": {"label": "Risque qualité de service", "description": "Dégradation SLA, incidents récurrents"},
    "security": {"label": "Risque sécurité", "description": "Fuites de données, cyberattaques, conformité"},
    "supply_chain": {"label": "Risque supply chain", "description": "Ruptures, pénuries, délais rallongés"},
    "regulatory": {"label": "Risque réglementaire", "description": "Changement de réglementation affectant le fournisseur"},
    "reputation": {"label": "Risque réputationnel", "description": "Mauvaise presse, scandales, ESG"},
}

# In-memory monitoring store
_SUPPLIER_WATCHLIST: dict[str, dict[str, Any]] = {}


# ── Handlers ─────────────────────────────────────────────────────────────────

async def handle_supplier_search(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Search and identify suppliers in a category."""
    category = arguments.get("category", "saas")
    query = arguments.get("query", "")
    budget_max = arguments.get("budget_max")
    users = arguments.get("users")
    geography = arguments.get("geography", "France")
    requirements = arguments.get("requirements", [])

    cat_data = _SUPPLIER_CATEGORIES.get(category)
    if not cat_data:
        return [{"type": "text", "text": json.dumps({
            "ok": False,
            "error": f"Unknown category: {category}. Valid: {list(_SUPPLIER_CATEGORIES.keys())}",
        })}]

    search_result: dict[str, Any] = {
        "ok": True,
        "category": category,
        "category_label": cat_data["label"],
        "query": query,
        "geography": geography,
        "recommended_sources": cat_data["sources"],
        "search_criteria": {
            "budget_max": budget_max,
            "users": users,
            "requirements": requirements,
        },
        "methodology": [
            f"1. Rechercher sur {', '.join(cat_data['sources'][:3])} avec les critères définis",
            "2. Filtrer par budget, géographie, et exigences techniques",
            "3. Présélectionner 5-8 candidats avec profil complet",
            "4. Shortlister 3-4 pour évaluation détaillée",
        ],
        "next_step": "Utiliser openclaw_supplier_evaluate pour scorer les candidats shortlistés",
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Sourcing par IA — devis et vérifications directes requis.",
    }

    return [{"type": "text", "text": json.dumps(search_result, ensure_ascii=False, indent=2)}]


async def handle_supplier_evaluate(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Multi-criteria supplier evaluation."""
    suppliers = arguments.get("suppliers", [])
    custom_scores = arguments.get("scores", {})
    custom_weights = arguments.get("criteria", {})

    if not suppliers:
        return [{"type": "text", "text": json.dumps({
            "ok": False, "error": "At least one supplier is required.",
        })}]

    # Build weights
    weights: dict[str, float] = {}
    total_weight = 0
    for crit_data in _EVALUATION_CRITERIA:
        crit = crit_data["criterion"]
        w = custom_weights.get(crit, crit_data["default_weight"])
        weights[crit] = w
        total_weight += w

    # Score each supplier
    results: list[dict[str, Any]] = []
    for supplier in suppliers:
        supplier_scores = custom_scores.get(supplier, {})
        criteria_details: dict[str, Any] = {}
        weighted_total = 0.0

        for crit_data in _EVALUATION_CRITERIA:
            crit = crit_data["criterion"]
            raw_score = supplier_scores.get(crit, 5)  # default 5/10
            weight = weights[crit]
            weighted = raw_score * weight / max(total_weight, 1) * 10
            criteria_details[crit] = {
                "label": crit_data["label"],
                "raw_score": raw_score,
                "weight": weight,
                "weighted_score": round(weighted, 2),
            }
            weighted_total += weighted

        results.append({
            "supplier": supplier,
            "total_score": round(weighted_total, 1),
            "criteria": criteria_details,
        })

    # Sort by score
    results.sort(key=lambda x: x["total_score"], reverse=True)

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "suppliers_evaluated": len(results),
        "criteria_used": len(_EVALUATION_CRITERIA),
        "results": results,
        "recommended": results[0]["supplier"] if results else None,
        "recommended_score": results[0]["total_score"] if results else None,
        "runner_up": results[1]["supplier"] if len(results) > 1 else None,
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Évaluation par IA — devis et références à vérifier.",
    }, ensure_ascii=False, indent=2)}]


async def handle_supplier_tco_analyze(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Total Cost of Ownership analysis."""
    suppliers = arguments.get("suppliers", [])
    volume = arguments.get("volume", 1)
    horizon_years = arguments.get("horizon_years", 3)
    unit_prices = arguments.get("unit_prices", {})
    include_hidden_costs = arguments.get("include_hidden_costs", True)

    if not suppliers:
        return [{"type": "text", "text": json.dumps({
            "ok": False, "error": "At least one supplier is required.",
        })}]

    analyses: list[dict[str, Any]] = []
    for supplier in suppliers:
        base_price = unit_prices.get(supplier, 100)
        annual_license = base_price * volume * 12  # monthly to annual

        cost_breakdown: dict[str, float] = {
            "license_annual": round(annual_license),
        }

        if include_hidden_costs:
            cost_breakdown["integration_setup"] = round(annual_license * 0.15)  # 15% first year
            cost_breakdown["training"] = round(volume * 50)  # 50€ per user training
            cost_breakdown["support_premium"] = round(annual_license * 0.10)  # 10% support
            cost_breakdown["migration_data"] = round(annual_license * 0.05)   # 5% data migration
            cost_breakdown["exit_cost_estimated"] = round(annual_license * 0.20)  # 20% exit

        # Multi-year projection
        yearly: list[dict[str, Any]] = []
        total_tco = 0.0
        for year in range(1, horizon_years + 1):
            year_cost = annual_license * (1.05 ** (year - 1))  # 5% annual increase
            if year == 1 and include_hidden_costs:
                year_cost += cost_breakdown.get("integration_setup", 0) + cost_breakdown.get("training", 0) + cost_breakdown.get("migration_data", 0)
            if include_hidden_costs:
                year_cost += cost_breakdown.get("support_premium", 0)

            yearly.append({"year": year, "cost": round(year_cost)})
            total_tco += year_cost

        analyses.append({
            "supplier": supplier,
            "unit_price_monthly": base_price,
            "volume": volume,
            "cost_breakdown": cost_breakdown,
            "yearly_projection": yearly,
            "total_tco": round(total_tco),
            "monthly_average": round(total_tco / (horizon_years * 12)),
        })

    # Sort by TCO
    analyses.sort(key=lambda x: x["total_tco"])

    cheapest = analyses[0] if analyses else None
    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "suppliers_compared": len(analyses),
        "horizon_years": horizon_years,
        "analyses": analyses,
        "recommended": cheapest["supplier"] if cheapest else None,
        "best_tco": cheapest["total_tco"] if cheapest else None,
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Analyse TCO par IA — devis réels requis pour validation.",
    }, ensure_ascii=False, indent=2)}]


async def handle_supplier_contract_check(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Contract clause analysis."""
    supplier = arguments.get("supplier", "")
    contract_type = arguments.get("contract_type", "SaaS")
    arguments.get("requirements", [])
    existing_clauses = arguments.get("existing_clauses", [])

    clause_analysis: list[dict[str, Any]] = []
    missing_critical = 0
    missing_high = 0

    for clause_def in _CONTRACT_CLAUSES:
        clause_name = clause_def["clause"]
        present = clause_name in existing_clauses

        status = "PRESENT" if present else "MISSING"
        if not present:
            if clause_def["priority"] == "CRITICAL":
                missing_critical += 1
            elif clause_def["priority"] == "HIGH":
                missing_high += 1

        clause_analysis.append({
            "clause": clause_name,
            "label": clause_def["label"],
            "priority": clause_def["priority"],
            "status": status,
            "description": clause_def["description"],
            "recommendation": f"Ajouter cette clause ({clause_def['priority']})" if not present else "OK",
        })

    # Sort by priority then status
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    clause_analysis.sort(key=lambda x: (priority_order.get(x["priority"], 5), x["status"] == "PRESENT"))

    overall_score = "CRITICAL" if missing_critical > 0 else "WARNING" if missing_high > 0 else "OK"

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "supplier": supplier,
        "contract_type": contract_type,
        "clauses_analyzed": len(clause_analysis),
        "missing_critical": missing_critical,
        "missing_high": missing_high,
        "overall_score": overall_score,
        "clauses": clause_analysis,
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Analyse contractuelle par IA — validation juridique requise.",
    }, ensure_ascii=False, indent=2)}]


async def handle_supplier_risk_monitor(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Supplier risk monitoring — CRUD watchlist."""
    action = arguments.get("action", "status")
    supplier = arguments.get("supplier", "")
    watch = arguments.get("watch", [])
    notes = arguments.get("notes")

    if action == "add":
        if not supplier:
            return [{"type": "text", "text": json.dumps({"ok": False, "error": "supplier is required for 'add'"})}]
        risk_details: list[dict[str, Any]] = []
        for risk_key in (watch or list(_RISK_CATEGORIES.keys())[:3]):
            risk_data = _RISK_CATEGORIES.get(risk_key)
            if risk_data:
                risk_details.append({
                    "risk": risk_key,
                    "label": risk_data["label"],
                    "description": risk_data["description"],
                    "current_level": "UNKNOWN",
                })
        _SUPPLIER_WATCHLIST[supplier] = {
            "supplier": supplier,
            "watched_risks": risk_details,
            "notes": notes,
            "added_at": datetime.now(UTC).isoformat(),
            "last_checked": None,
        }
        return [{"type": "text", "text": json.dumps({
            "ok": True, "action": "added", "supplier": supplier,
            "risks_monitored": len(risk_details),
        }, ensure_ascii=False, indent=2)}]

    elif action == "remove":
        if supplier in _SUPPLIER_WATCHLIST:
            del _SUPPLIER_WATCHLIST[supplier]
            return [{"type": "text", "text": json.dumps({"ok": True, "action": "removed", "supplier": supplier})}]
        return [{"type": "text", "text": json.dumps({"ok": False, "error": f"Supplier '{supplier}' not in watchlist"})}]

    elif action == "update":
        if supplier not in _SUPPLIER_WATCHLIST:
            return [{"type": "text", "text": json.dumps({"ok": False, "error": f"Supplier '{supplier}' not in watchlist"})}]
        entry = _SUPPLIER_WATCHLIST[supplier]
        if notes:
            entry["notes"] = notes
        entry["last_checked"] = datetime.now(UTC).isoformat()
        return [{"type": "text", "text": json.dumps({"ok": True, "action": "updated", "supplier": supplier})}]

    elif action == "status":
        if supplier:
            entry = _SUPPLIER_WATCHLIST.get(supplier)
            if not entry:
                return [{"type": "text", "text": json.dumps({"ok": False, "error": f"Supplier '{supplier}' not in watchlist"})}]
            return [{"type": "text", "text": json.dumps({"ok": True, "supplier": entry}, ensure_ascii=False, indent=2)}]
        return [{"type": "text", "text": json.dumps({
            "ok": True,
            "watchlist_count": len(_SUPPLIER_WATCHLIST),
            "suppliers": list(_SUPPLIER_WATCHLIST.keys()),
        }, ensure_ascii=False, indent=2)}]

    elif action == "export":
        return [{"type": "text", "text": json.dumps({
            "ok": True,
            "export": list(_SUPPLIER_WATCHLIST.values()),
            "total": len(_SUPPLIER_WATCHLIST),
            "exported_at": datetime.now(UTC).isoformat(),
        }, ensure_ascii=False, indent=2)}]

    return [{"type": "text", "text": json.dumps({"ok": False, "error": f"Unknown action: {action}"})}]


# ── Tool definitions ─────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_supplier_search",
        "title": "Suppliers — Supplier Search",
        "description": "Market-wide supplier sourcing — identifies potential suppliers by category, budget, geography. Provides recommended sources and methodology.",
        "category": "procurement",
        "annotations": {"title": "Suppliers — Supplier Search", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "category": {"type": "string"}, "recommended_sources": {"type": "array"}}},
        "handler": handle_supplier_search,
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Supplier category: saas, cloud, services, hardware, office, logistics, raw_materials, marketing, consulting, telecom, insurance, accounting"},
                "query": {"type": "string", "description": "Search query / description of need"},
                "budget_max": {"type": "number", "description": "Maximum budget (€/month or €/unit)"},
                "users": {"type": "integer", "description": "Number of users (for SaaS)"},
                "geography": {"type": "string", "description": "Geography preference"},
                "requirements": {"type": "array", "items": {"type": "string"}, "description": "Specific requirements"},
            },
        },
    },
    {
        "name": "openclaw_supplier_evaluate",
        "title": "Suppliers — Evaluate & Score",
        "description": "Multi-criteria supplier evaluation with 15+ weighted criteria. Scores quality, price, delivery, support, security, and more. Outputs ranked matrix.",
        "category": "procurement",
        "annotations": {"title": "Suppliers — Evaluate & Score", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "recommended": {"type": "string"}, "results": {"type": "array"}}},
        "handler": handle_supplier_evaluate,
        "inputSchema": {
            "type": "object",
            "properties": {
                "suppliers": {"type": "array", "items": {"type": "string"}, "description": "List of suppliers to evaluate"},
                "scores": {"type": "object", "description": "Custom scores: {supplier: {criterion: score(1-10)}}"},
                "criteria": {"type": "object", "description": "Custom weights: {criterion: weight}"},
            },
            "required": ["suppliers"],
        },
    },
    {
        "name": "openclaw_supplier_tco_analyze",
        "title": "Suppliers — TCO Analysis",
        "description": "Total Cost of Ownership analysis over 3-5 years. Includes license, integration, training, support, migration, and exit costs.",
        "category": "procurement",
        "annotations": {"title": "Suppliers — TCO Analysis", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "recommended": {"type": "string"}, "analyses": {"type": "array"}}},
        "handler": handle_supplier_tco_analyze,
        "inputSchema": {
            "type": "object",
            "properties": {
                "suppliers": {"type": "array", "items": {"type": "string"}, "description": "Suppliers to compare"},
                "volume": {"type": "integer", "description": "Number of units/licenses/users"},
                "horizon_years": {"type": "integer", "description": "TCO horizon in years"},
                "unit_prices": {"type": "object", "description": "Monthly unit prices: {supplier: price}"},
                "include_hidden_costs": {"type": "boolean", "description": "Include integration, training, exit costs?"},
            },
            "required": ["suppliers"],
        },
    },
    {
        "name": "openclaw_supplier_contract_check",
        "title": "Suppliers — Contract Check",
        "description": "Contract clause analysis — checks SLA, penalties, data protection (DPA), reversibility, IP, NDA, and more against best practices.",
        "category": "procurement",
        "annotations": {"title": "Suppliers — Contract Check", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "overall_score": {"type": "string"}, "clauses": {"type": "array"}}},
        "handler": handle_supplier_contract_check,
        "inputSchema": {
            "type": "object",
            "properties": {
                "supplier": {"type": "string", "description": "Supplier name"},
                "contract_type": {"type": "string", "description": "Type: SaaS, services, hardware, etc."},
                "requirements": {"type": "array", "items": {"type": "string"}, "description": "Specific contract requirements"},
                "existing_clauses": {"type": "array", "items": {"type": "string"}, "description": "Clauses already present in the contract"},
            },
        },
    },
    {
        "name": "openclaw_supplier_risk_monitor",
        "title": "Suppliers — Risk Monitor",
        "description": "Continuous supplier risk monitoring — add/remove/update/status/export watchlist. Tracks financial, dependency, geopolitical, and service level risks.",
        "category": "procurement",
        "annotations": {"title": "Suppliers — Risk Monitor", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "action": {"type": "string"}}},
        "handler": handle_supplier_risk_monitor,
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "Action: add, remove, update, status, export"},
                "supplier": {"type": "string", "description": "Supplier name"},
                "watch": {"type": "array", "items": {"type": "string"}, "description": "Risk categories to watch: financial, dependency, geopolitical, service_level, security, supply_chain, regulatory, reputation"},
                "notes": {"type": "string", "description": "Notes about the supplier"},
            },
        },
    },
]
