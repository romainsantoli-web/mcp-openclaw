"""
legal_status.py — Legal Status & Corporate Structuring tools

Implements 5 tools for the Legal Status department:
  - Legal form comparison (SAS, SARL, SASU, EURL, etc.)
  - Tax simulation (IS vs IR, holding structures)
  - Social protection analysis (TNS vs assimilé salarié)
  - Governance structuring (statuts, pactes, organes)
  - Creation compliance checklist

Tools exposed (5):
  firm_legal_status_compare       — multi-criteria legal form comparison
  firm_legal_tax_simulate         — IS/IR simulation over 3-5 years
  firm_legal_social_protection    — social protection analysis by status
  firm_legal_governance_audit     — governance structure recommendations
  firm_legal_creation_checklist   — post-creation compliance checklist
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_LEGAL_FORMS: dict[str, dict[str, Any]] = {
    "SAS": {
        "full_name": "Société par Actions Simplifiée",
        "min_capital": 1,
        "min_associates": 2,
        "max_associates": None,
        "limited_liability": True,
        "social_regime": "assimile_salarie",
        "social_charges_rate": 0.65,
        "default_tax": "IS",
        "can_opt_ir": True,
        "ir_duration_max_years": 5,
        "bspce_eligible": True,
        "fundraising_flexibility": "HIGH",
        "governance_flexibility": "HIGH",
        "share_types": ["ordinaires", "preference", "BSA", "BSPCE", "AGA"],
        "annual_accounts": True,
        "statutory_auditor_threshold": "8M CA or 4M bilan or 50 salariés",
    },
    "SASU": {
        "full_name": "Société par Actions Simplifiée Unipersonnelle",
        "min_capital": 1,
        "min_associates": 1,
        "max_associates": 1,
        "limited_liability": True,
        "social_regime": "assimile_salarie",
        "social_charges_rate": 0.65,
        "default_tax": "IS",
        "can_opt_ir": True,
        "ir_duration_max_years": 5,
        "bspce_eligible": True,
        "fundraising_flexibility": "HIGH",
        "governance_flexibility": "HIGH",
        "share_types": ["ordinaires", "preference", "BSA", "AGA"],
        "annual_accounts": True,
        "statutory_auditor_threshold": "8M CA or 4M bilan or 50 salariés",
    },
    "SARL": {
        "full_name": "Société à Responsabilité Limitée",
        "min_capital": 1,
        "min_associates": 2,
        "max_associates": 100,
        "limited_liability": True,
        "social_regime": "TNS",
        "social_charges_rate": 0.45,
        "default_tax": "IS",
        "can_opt_ir": True,
        "ir_duration_max_years": 5,
        "bspce_eligible": False,
        "fundraising_flexibility": "LOW",
        "governance_flexibility": "LOW",
        "share_types": ["parts_sociales"],
        "annual_accounts": True,
        "statutory_auditor_threshold": "8M CA or 4M bilan or 50 salariés",
    },
    "EURL": {
        "full_name": "Entreprise Unipersonnelle à Responsabilité Limitée",
        "min_capital": 1,
        "min_associates": 1,
        "max_associates": 1,
        "limited_liability": True,
        "social_regime": "TNS",
        "social_charges_rate": 0.45,
        "default_tax": "IR",
        "can_opt_ir": True,
        "ir_duration_max_years": None,
        "bspce_eligible": False,
        "fundraising_flexibility": "NONE",
        "governance_flexibility": "LOW",
        "share_types": ["parts_sociales"],
        "annual_accounts": True,
        "statutory_auditor_threshold": "8M CA or 4M bilan or 50 salariés",
    },
    "SA": {
        "full_name": "Société Anonyme",
        "min_capital": 37000,
        "min_associates": 2,
        "max_associates": None,
        "limited_liability": True,
        "social_regime": "assimile_salarie",
        "social_charges_rate": 0.65,
        "default_tax": "IS",
        "can_opt_ir": False,
        "ir_duration_max_years": 0,
        "bspce_eligible": True,
        "fundraising_flexibility": "HIGH",
        "governance_flexibility": "MEDIUM",
        "share_types": ["ordinaires", "preference", "BSA", "BSPCE", "AGA"],
        "annual_accounts": True,
        "statutory_auditor_threshold": "obligatoire",
    },
    "MICRO": {
        "full_name": "Micro-entreprise (Auto-entrepreneur)",
        "min_capital": 0,
        "min_associates": 1,
        "max_associates": 1,
        "limited_liability": False,
        "social_regime": "TNS_micro",
        "social_charges_rate": 0.22,
        "default_tax": "IR_micro",
        "can_opt_ir": True,
        "ir_duration_max_years": None,
        "bspce_eligible": False,
        "fundraising_flexibility": "NONE",
        "governance_flexibility": "NONE",
        "share_types": [],
        "annual_accounts": False,
        "statutory_auditor_threshold": "N/A",
    },
    "SCI": {
        "full_name": "Société Civile Immobilière",
        "min_capital": 1,
        "min_associates": 2,
        "max_associates": None,
        "limited_liability": False,
        "social_regime": "N/A",
        "social_charges_rate": 0.0,
        "default_tax": "IR",
        "can_opt_ir": True,
        "ir_duration_max_years": None,
        "bspce_eligible": False,
        "fundraising_flexibility": "NONE",
        "governance_flexibility": "LOW",
        "share_types": ["parts_sociales"],
        "annual_accounts": True,
        "statutory_auditor_threshold": "N/A",
    },
}

_COMPARISON_CRITERIA = [
    "responsabilite_limitee",
    "capital_minimum",
    "charges_sociales",
    "regime_fiscal_defaut",
    "option_ir",
    "bspce_eligible",
    "flexibilite_levee_fonds",
    "flexibilite_gouvernance",
    "nombre_associes",
    "comptes_annuels",
    "types_titres",
    "commissaire_aux_comptes",
    "transmission_parts",
    "protection_patrimoine",
    "complexite_creation",
]

_IS_RATES = {
    "reduced": {"threshold": 42500, "rate": 0.15},
    "standard": {"rate": 0.25},
}

_SOCIAL_REGIMES = {
    "TNS": {
        "label": "Travailleur Non Salarié",
        "charges_rate": 0.45,
        "unemployment": False,
        "retirement_base": "RSI/SSI",
        "health": "SSI",
        "prevoyance_mandatory": False,
    },
    "assimile_salarie": {
        "label": "Assimilé Salarié",
        "charges_rate": 0.65,
        "unemployment": False,
        "retirement_base": "AGIRC-ARRCO",
        "health": "CPAM",
        "prevoyance_mandatory": True,
    },
    "TNS_micro": {
        "label": "Micro-entrepreneur",
        "charges_rate": 0.22,
        "unemployment": False,
        "retirement_base": "SSI",
        "health": "SSI",
        "prevoyance_mandatory": False,
    },
}

_GOVERNANCE_CLAUSES = [
    "agrement_cession",
    "preemption",
    "inalienabilite",
    "drag_along",
    "tag_along",
    "good_leaver_bad_leaver",
    "anti_dilution",
    "non_concurrence",
    "clause_de_sortie",
    "repartition_benefices",
    "majorites_qualifiees",
    "droit_veto",
]

_CREATION_STEPS = [
    {"step": "Rédaction des statuts", "delay": "1-2 semaines", "cost": "500-2000€", "responsible": "Avocat / Legal"},
    {"step": "Dépôt du capital social", "delay": "1-2 jours", "cost": "0€ (virement)", "responsible": "Banque"},
    {"step": "Publication annonce légale", "delay": "1 jour", "cost": "150-250€", "responsible": "JAL"},
    {"step": "Immatriculation (Guichet unique INPI)", "delay": "1-4 semaines", "cost": "37-70€", "responsible": "Fondateur"},
    {"step": "Obtention K-bis", "delay": "3-7 jours", "cost": "inclus", "responsible": "Greffe"},
    {"step": "Ouverture compte bancaire définitif", "delay": "1-2 semaines", "cost": "0-30€/mois", "responsible": "Banque"},
    {"step": "Déclaration CFE / choix régime TVA", "delay": "30 jours post-création", "cost": "0€", "responsible": "SIE"},
    {"step": "Affiliation URSSAF / prévoyance", "delay": "automatique", "cost": "selon statut", "responsible": "URSSAF"},
    {"step": "Assurance RC Pro", "delay": "J+1", "cost": "300-2000€/an", "responsible": "Assureur"},
    {"step": "Mise en place comptabilité", "delay": "J+1", "cost": "1000-5000€/an", "responsible": "Expert-comptable"},
]


# ── Handlers ─────────────────────────────────────────────────────────────────

async def handle_legal_status_compare(
    project_type: str = "startup",
    founders: int = 1,
    revenue_y1: float = 0,
    fundraising: bool = False,
    sector: str = "tech",
    criteria_weights: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Compare legal forms with multi-criteria scoring."""

    # Filter relevant forms based on founder count
    relevant_forms: dict[str, dict[str, Any]] = {}
    for form_name, form_data in _LEGAL_FORMS.items():
        min_assoc = form_data["min_associates"]
        max_assoc = form_data["max_associates"]
        if founders >= min_assoc and (max_assoc is None or founders <= max_assoc):
            relevant_forms[form_name] = form_data

    # Score each form
    scored_forms: list[dict[str, Any]] = []
    for form_name, form_data in relevant_forms.items():
        score = 0.0
        details: dict[str, Any] = {"form": form_name, "full_name": form_data["full_name"]}

        # Liability protection
        if form_data["limited_liability"]:
            score += 15
            details["liability"] = "Limitée aux apports"
        else:
            details["liability"] = "Illimitée (patrimoine personnel exposé)"

        # Social charges efficiency
        charges_score = max(0, (1 - form_data["social_charges_rate"]) * 20)
        score += charges_score
        details["social_charges_rate"] = f"{form_data['social_charges_rate'] * 100:.0f}%"

        # Fundraising readiness
        if fundraising:
            flex_scores = {"HIGH": 20, "MEDIUM": 10, "LOW": 5, "NONE": 0}
            score += flex_scores.get(form_data["fundraising_flexibility"], 0)
        details["fundraising_flexibility"] = form_data["fundraising_flexibility"]

        # BSPCE eligibility (important for tech startups)
        if form_data["bspce_eligible"]:
            score += 10
        details["bspce_eligible"] = form_data["bspce_eligible"]

        # Governance flexibility
        flex_scores_gov = {"HIGH": 10, "MEDIUM": 5, "LOW": 2, "NONE": 0}
        score += flex_scores_gov.get(form_data["governance_flexibility"], 0)
        details["governance_flexibility"] = form_data["governance_flexibility"]

        # Revenue threshold consideration
        if revenue_y1 > 77700 and form_name == "MICRO":
            score -= 20  # Exceeds micro threshold
            details["warning"] = "Dépasse le plafond micro-entreprise (77.700€ services)"

        details["score"] = round(score, 1)
        details["capital_minimum"] = form_data["min_capital"]
        details["regime_fiscal"] = form_data["default_tax"]
        details["social_regime"] = form_data["social_regime"]
        details["share_types"] = form_data["share_types"]
        scored_forms.append(details)

    # Sort by score
    scored_forms.sort(key=lambda x: x["score"], reverse=True)

    recommended = scored_forms[0] if scored_forms else None

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "project_profile": {
            "type": project_type,
            "founders": founders,
            "revenue_y1": revenue_y1,
            "fundraising_planned": fundraising,
            "sector": sector,
        },
        "forms_analyzed": len(scored_forms),
        "comparison": scored_forms,
        "recommended": recommended["form"] if recommended else None,
        "recommended_score": recommended["score"] if recommended else None,
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Analyse générée par IA — consultation d'un avocat requise.",
    }, ensure_ascii=False, indent=2)}]


async def handle_legal_tax_simulate(
    legal_form: str = "SAS",
    revenue: float = 100000,
    salary: float = 0,
    dividends: float = 0,
    horizon_years: int = 3,
    growth_rate: float = 0.1,
    holding: bool = False,
) -> list[dict[str, Any]]:
    """Simulate IS vs IR taxation over multiple years."""

    form_data = _LEGAL_FORMS.get(legal_form)
    if not form_data:
        return [{"type": "text", "text": json.dumps({
            "ok": False, "error": f"Unknown legal form: {legal_form}. Valid: {list(_LEGAL_FORMS.keys())}",
        })}]

    projections: list[dict[str, Any]] = []
    for year in range(1, horizon_years + 1):
        year_revenue = revenue * ((1 + growth_rate) ** (year - 1))
        charges_rate = form_data["social_charges_rate"]
        gross_salary = salary * ((1 + growth_rate * 0.5) ** (year - 1))
        social_charges = gross_salary * charges_rate
        total_salary_cost = gross_salary + social_charges

        # IS calculation
        taxable_profit_is = year_revenue - total_salary_cost
        if taxable_profit_is <= 0:
            is_tax = 0.0
        elif taxable_profit_is <= _IS_RATES["reduced"]["threshold"]:
            is_tax = taxable_profit_is * _IS_RATES["reduced"]["rate"]
        else:
            is_tax = (
                _IS_RATES["reduced"]["threshold"] * _IS_RATES["reduced"]["rate"]
                + (taxable_profit_is - _IS_RATES["reduced"]["threshold"]) * _IS_RATES["standard"]["rate"]
            )

        net_profit_is = taxable_profit_is - is_tax

        # Dividends (flat tax 30%)
        year_dividends = min(dividends * ((1 + growth_rate) ** (year - 1)), net_profit_is * 0.8)
        dividend_tax = year_dividends * 0.30
        net_dividends = year_dividends - dividend_tax

        # Net salary (after employee charges ~22%)
        net_salary = gross_salary * 0.78

        # Holding benefit
        holding_benefit = 0.0
        if holding and year_dividends > 0:
            # Régime mère-fille: 95% exonération
            holding_benefit = year_dividends * 0.30 * 0.95
            dividend_tax *= 0.05

        total_net_remuneration = net_salary + net_dividends + holding_benefit

        projections.append({
            "year": year,
            "revenue": round(year_revenue),
            "gross_salary": round(gross_salary),
            "social_charges": round(social_charges),
            "taxable_profit": round(taxable_profit_is),
            "is_tax": round(is_tax),
            "net_profit": round(net_profit_is),
            "dividends_gross": round(year_dividends),
            "dividend_tax": round(dividend_tax),
            "net_dividends": round(net_dividends),
            "net_salary": round(net_salary),
            "holding_benefit": round(holding_benefit),
            "total_net_remuneration": round(total_net_remuneration),
        })

    total_tax_paid = sum(p["is_tax"] + p["dividend_tax"] + p["social_charges"] for p in projections)
    total_net_rem = sum(p["total_net_remuneration"] for p in projections)

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "legal_form": legal_form,
        "simulation_params": {
            "revenue_y1": revenue,
            "salary_y1": salary,
            "dividends_y1": dividends,
            "growth_rate": growth_rate,
            "holding": holding,
            "horizon_years": horizon_years,
        },
        "projections": projections,
        "summary": {
            "total_tax_paid": round(total_tax_paid),
            "total_net_remuneration": round(total_net_rem),
            "effective_tax_rate": round(total_tax_paid / max(sum(p["revenue"] for p in projections), 1) * 100, 1),
        },
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Simulation fiscale par IA — validation par expert-comptable requise.",
    }, ensure_ascii=False, indent=2)}]


async def handle_legal_social_protection(
    status: str = "assimile_salarie",
    salary: float = 50000,
    include_options: bool = True,
) -> list[dict[str, Any]]:
    """Analyze social protection by status."""

    regime = _SOCIAL_REGIMES.get(status)
    if not regime:
        return [{"type": "text", "text": json.dumps({
            "ok": False, "error": f"Unknown status: {status}. Valid: {list(_SOCIAL_REGIMES.keys())}",
        })}]

    annual_charges = salary * regime["charges_rate"]
    net_after_charges = salary - annual_charges

    coverage: dict[str, Any] = {
        "health": regime["health"],
        "retirement_base": regime["retirement_base"],
        "unemployment": regime["unemployment"],
        "prevoyance_mandatory": regime["prevoyance_mandatory"],
    }

    comparison: list[dict[str, Any]] = []
    if include_options:
        for regime_name, regime_data in _SOCIAL_REGIMES.items():
            charges = salary * regime_data["charges_rate"]
            comparison.append({
                "regime": regime_name,
                "label": regime_data["label"],
                "annual_charges": round(charges),
                "net_income": round(salary - charges),
                "charges_rate": f"{regime_data['charges_rate'] * 100:.0f}%",
                "unemployment_coverage": regime_data["unemployment"],
                "retirement": regime_data["retirement_base"],
                "health": regime_data["health"],
            })

    recommendations: list[str] = []
    if not regime["unemployment"]:
        recommendations.append("Prévoir une assurance perte d'emploi (GSC/APPI) — pas de chômage Pôle Emploi")
    if not regime["prevoyance_mandatory"]:
        recommendations.append("Souscrire une prévoyance Madelin (déductible) — incapacité/décès non couverts")
    recommendations.append("Contrat retraite complémentaire PER (ex-Madelin) recommandé")

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "status": status,
        "regime": regime["label"],
        "salary_base": salary,
        "annual_charges": round(annual_charges),
        "net_after_charges": round(net_after_charges),
        "coverage": coverage,
        "comparison": comparison,
        "recommendations": recommendations,
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Analyse sociale par IA — consultation d'un expert requise.",
    }, ensure_ascii=False, indent=2)}]


async def handle_legal_governance_audit(
    legal_form: str = "SAS",
    founders: int = 2,
    has_investors: bool = False,
    specific_clauses: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Audit governance structure and recommend clauses."""

    form_data = _LEGAL_FORMS.get(legal_form)
    if not form_data:
        return [{"type": "text", "text": json.dumps({
            "ok": False, "error": f"Unknown legal form: {legal_form}",
        })}]

    recommended_clauses: list[dict[str, Any]] = []
    for clause in _GOVERNANCE_CLAUSES:
        priority = "RECOMMENDED"
        reason = ""

        if clause == "agrement_cession":
            priority = "CRITICAL" if founders > 1 else "OPTIONAL"
            reason = "Contrôle des entrées au capital"
        elif clause == "drag_along" and has_investors:
            priority = "CRITICAL"
            reason = "Requis par les investisseurs pour garantir la sortie"
        elif clause == "tag_along" and founders > 1:
            priority = "CRITICAL"
            reason = "Protection des minoritaires en cas de cession"
        elif clause == "good_leaver_bad_leaver" and has_investors:
            priority = "CRITICAL"
            reason = "Standard investisseurs pour le vesting des fondateurs"
        elif clause == "anti_dilution" and has_investors:
            priority = "HIGH"
            reason = "Protection contre les down rounds"
        elif clause == "non_concurrence":
            priority = "HIGH"
            reason = "Protection de l'activité en cas de départ"
        elif clause == "clause_de_sortie":
            priority = "HIGH" if founders > 1 else "MEDIUM"
            reason = "Mécanisme de valorisation et de sortie"
        elif clause == "droit_veto" and has_investors:
            priority = "HIGH"
            reason = "Investisseurs veulent un veto sur les décisions stratégiques"
        else:
            reason = "Clause de gouvernance standard"

        if specific_clauses and clause not in specific_clauses:
            continue

        recommended_clauses.append({
            "clause": clause,
            "priority": priority,
            "reason": reason,
            "applicable_to": legal_form,
        })

    # Sort by priority
    priority_order = {"CRITICAL": 0, "HIGH": 1, "RECOMMENDED": 2, "MEDIUM": 3, "OPTIONAL": 4}
    recommended_clauses.sort(key=lambda x: priority_order.get(x["priority"], 5))

    governance_structure = {
        "legal_form": legal_form,
        "president": True,
        "directeur_general": founders > 1,
        "conseil_administration": legal_form == "SA",
        "ag_ordinaire": True,
        "ag_extraordinaire": True,
        "commissaire_comptes": form_data["statutory_auditor_threshold"],
    }

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "legal_form": legal_form,
        "founders": founders,
        "has_investors": has_investors,
        "governance_structure": governance_structure,
        "recommended_clauses": recommended_clauses,
        "clause_count": len(recommended_clauses),
        "critical_clauses": len([c for c in recommended_clauses if c["priority"] == "CRITICAL"]),
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Analyse de gouvernance par IA — rédaction par un avocat requise.",
    }, ensure_ascii=False, indent=2)}]


async def handle_legal_creation_checklist(
    legal_form: str = "SAS",
    sector: str = "tech",
    geography: str = "France",
) -> list[dict[str, Any]]:
    """Generate post-creation compliance checklist."""

    form_data = _LEGAL_FORMS.get(legal_form)
    if not form_data:
        return [{"type": "text", "text": json.dumps({
            "ok": False, "error": f"Unknown legal form: {legal_form}",
        })}]

    # Build checklist
    checklist = [dict(s, order=i + 1) for i, s in enumerate(_CREATION_STEPS)]

    # Estimated total cost
    min_cost = 500 + 0 + 150 + 37 + 0 + 300 + 1000  # ~1987€
    max_cost = 2000 + 0 + 250 + 70 + 30 * 12 + 2000 + 5000  # ~9680€

    # Annual obligations
    annual_obligations = [
        {"obligation": "Assemblée Générale annuelle", "deadline": "6 mois après clôture", "penalty": "Amende + nullité"},
        {"obligation": "Dépôt des comptes annuels (greffe)", "deadline": "7 mois après clôture", "penalty": "Amende 1.500€"},
        {"obligation": "Déclaration IS / IR", "deadline": "Mai N+1", "penalty": "Majoration 10-40%"},
        {"obligation": "CFE (Cotisation Foncière des Entreprises)", "deadline": "15 décembre", "penalty": "Majoration 5%"},
        {"obligation": "TVA (déclaration mensuelle/trimestrielle)", "deadline": "selon régime", "penalty": "Majoration 10%"},
        {"obligation": "DSN (Déclaration Sociale Nominative)", "deadline": "mensuelle si salariés", "penalty": "Pénalité"},
    ]

    if not form_data["annual_accounts"]:
        annual_obligations = [o for o in annual_obligations if "comptes annuels" not in o["obligation"].lower()]

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "legal_form": legal_form,
        "sector": sector,
        "geography": geography,
        "creation_steps": checklist,
        "estimated_cost": {"min": f"{min_cost}€", "max": f"{max_cost}€"},
        "annual_obligations": annual_obligations,
        "total_steps": len(checklist),
        "estimated_timeline": "4-8 semaines",
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Checklist générée par IA — validation par un professionnel requise.",
    }, ensure_ascii=False, indent=2)}]


# ── Tool definitions ─────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "firm_legal_status_compare",
        "title": "Legal Status — Compare Legal Forms",
        "description": "Compare legal forms (SAS, SARL, SASU, EURL, etc.) with multi-criteria scoring matrix. Analyzes liability, tax regime, social charges, fundraising flexibility, and governance.",
        "category": "legal_status",
        "annotations": {"title": "Legal Status — Compare Legal Forms", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "forms_analyzed": {"type": "integer"}, "recommended": {"type": "string"}}},
        "handler": handle_legal_status_compare,
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_type": {"type": "string", "description": "Type of project (startup, freelance, holding, etc.)"},
                "founders": {"type": "integer", "description": "Number of founders/associates"},
                "revenue_y1": {"type": "number", "description": "Expected revenue Year 1 (€)"},
                "fundraising": {"type": "boolean", "description": "Planning to raise funds?"},
                "sector": {"type": "string", "description": "Business sector"},
                "criteria_weights": {"type": "object", "description": "Custom weights for scoring criteria"},
            },
        },
    },
    {
        "name": "firm_legal_tax_simulate",
        "title": "Legal Status — Tax Simulation",
        "description": "Tax simulation IS vs IR over 3-5 years. Includes salary/dividend optimization, holding structure benefits, and effective tax rate calculation.",
        "category": "legal_status",
        "annotations": {"title": "Legal Status — Tax Simulation", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "projections": {"type": "array"}, "summary": {"type": "object"}}},
        "handler": handle_legal_tax_simulate,
        "inputSchema": {
            "type": "object",
            "properties": {
                "legal_form": {"type": "string", "description": "Legal form (SAS, SARL, SASU, EURL, SA, MICRO)"},
                "revenue": {"type": "number", "description": "Annual revenue Year 1 (€)"},
                "salary": {"type": "number", "description": "Annual gross salary (€)"},
                "dividends": {"type": "number", "description": "Target annual dividends (€)"},
                "horizon_years": {"type": "integer", "description": "Simulation horizon in years (1-10)"},
                "growth_rate": {"type": "number", "description": "Annual revenue growth rate (0.1 = 10%)"},
                "holding": {"type": "boolean", "description": "Include holding structure (régime mère-fille)?"},
            },
        },
    },
    {
        "name": "firm_legal_social_protection",
        "title": "Legal Status — Social Protection Analysis",
        "description": "Social protection analysis by status — TNS vs assimilé salarié vs micro-entrepreneur. Compares charges, retirement, health, and unemployment coverage.",
        "category": "legal_status",
        "annotations": {"title": "Legal Status — Social Protection", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "regime": {"type": "string"}, "coverage": {"type": "object"}}},
        "handler": handle_legal_social_protection,
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "description": "Social status: TNS, assimile_salarie, TNS_micro"},
                "salary": {"type": "number", "description": "Annual salary/revenue base (€)"},
                "include_options": {"type": "boolean", "description": "Include comparison with all regimes?"},
            },
        },
    },
    {
        "name": "firm_legal_governance_audit",
        "title": "Legal Status — Governance Audit",
        "description": "Governance structure audit — recommends statutory clauses, pactes d'associés, and governance organs based on legal form and investor involvement.",
        "category": "legal_status",
        "annotations": {"title": "Legal Status — Governance Audit", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "recommended_clauses": {"type": "array"}, "critical_clauses": {"type": "integer"}}},
        "handler": handle_legal_governance_audit,
        "inputSchema": {
            "type": "object",
            "properties": {
                "legal_form": {"type": "string", "description": "Legal form (SAS, SARL, etc.)"},
                "founders": {"type": "integer", "description": "Number of founders"},
                "has_investors": {"type": "boolean", "description": "Are there external investors?"},
                "specific_clauses": {"type": "array", "items": {"type": "string"}, "description": "Specific clauses to evaluate"},
            },
        },
    },
    {
        "name": "firm_legal_creation_checklist",
        "title": "Legal Status — Creation Checklist",
        "description": "Post-creation compliance checklist — steps, costs, timeline, and annual obligations for the chosen legal form.",
        "category": "legal_status",
        "annotations": {"title": "Legal Status — Creation Checklist", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "creation_steps": {"type": "array"}, "annual_obligations": {"type": "array"}}},
        "handler": handle_legal_creation_checklist,
        "inputSchema": {
            "type": "object",
            "properties": {
                "legal_form": {"type": "string", "description": "Legal form (SAS, SARL, etc.)"},
                "sector": {"type": "string", "description": "Business sector"},
                "geography": {"type": "string", "description": "Country/region of creation"},
            },
        },
    },
]
