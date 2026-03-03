"""
location_strategy.py — Location Strategy & Site Selection tools

Implements 5 tools for the Location Strategy department:
  - Geo-economic analysis (talent pools, transport, ecosystem)
  - Real estate intelligence (availability, pricing, trends)
  - Multi-criteria site scoring (20+ weighted criteria)
  - Tax incentives and aid programs by territory
  - Total Cost of Occupation simulation

Tools exposed (5):
  openclaw_location_geo_analysis      — geo-economic analysis of candidate zones
  openclaw_location_real_estate       — real estate market intelligence
  openclaw_location_site_score        — multi-criteria site scoring matrix
  openclaw_location_incentives        — territorial tax incentives and aids
  openclaw_location_tco_simulate      — Total Cost of Occupation simulation
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_SCORING_CRITERIA: dict[str, dict[str, Any]] = {
    "transport_access": {"label": "Accessibilité transport", "default_weight": 15, "category": "infrastructure"},
    "talent_pool": {"label": "Bassin d'emploi qualifié", "default_weight": 15, "category": "workforce"},
    "price_sqm": {"label": "Prix au m² (loyer)", "default_weight": 20, "category": "cost"},
    "local_ecosystem": {"label": "Écosystème local (startups, clusters)", "default_weight": 10, "category": "ecosystem"},
    "quality_of_life": {"label": "Qualité de vie", "default_weight": 5, "category": "attractiveness"},
    "fiber_connectivity": {"label": "Fibre optique / connectivité", "default_weight": 8, "category": "infrastructure"},
    "parking_availability": {"label": "Stationnement", "default_weight": 3, "category": "infrastructure"},
    "restaurant_services": {"label": "Services de proximité (restaurants, etc.)", "default_weight": 2, "category": "attractiveness"},
    "expansion_potential": {"label": "Potentiel d'extension", "default_weight": 5, "category": "growth"},
    "tax_incentives": {"label": "Avantages fiscaux territoriaux", "default_weight": 7, "category": "cost"},
    "security": {"label": "Sécurité du quartier", "default_weight": 3, "category": "attractiveness"},
    "client_proximity": {"label": "Proximité clients/partenaires", "default_weight": 5, "category": "business"},
    "airport_access": {"label": "Accès aéroport international", "default_weight": 2, "category": "infrastructure"},
    "coworking_availability": {"label": "Offre coworking flexible", "default_weight": 3, "category": "flexibility"},
    "green_certification": {"label": "Certification environnementale (HQE/BREEAM)", "default_weight": 2, "category": "sustainability"},
    "public_transport_frequency": {"label": "Fréquence transports en commun", "default_weight": 5, "category": "infrastructure"},
    "housing_affordability": {"label": "Accessibilité logement (pour les salariés)", "default_weight": 3, "category": "attractiveness"},
    "university_proximity": {"label": "Proximité universités/écoles", "default_weight": 3, "category": "workforce"},
    "incubator_proximity": {"label": "Proximité incubateurs/pépinières", "default_weight": 2, "category": "ecosystem"},
    "natural_risk": {"label": "Risques naturels (inondation, sismique)", "default_weight": 2, "category": "risk"},
}

_PROPERTY_TYPES = {
    "bureau": "Bureaux (open space, cloisonné, flex)",
    "coworking": "Espace de coworking",
    "entrepot": "Entrepôt / logistique",
    "commerce": "Local commercial",
    "mixte": "Local mixte (bureau + stockage)",
    "atelier": "Atelier / local d'activité",
    "terrain": "Terrain nu",
}

_TAX_ZONES: dict[str, dict[str, Any]] = {
    "ZFU-TE": {
        "label": "Zone Franche Urbaine — Territoire Entrepreneur",
        "exo_is": "5 ans (100%), puis dégressif 3 ans",
        "exo_cfe": "5 ans",
        "exo_charges_sociales": "5 ans (50 salariés max)",
        "conditions": "Clause d'embauche locale (50%)",
    },
    "ZRR": {
        "label": "Zone de Revitalisation Rurale",
        "exo_is": "5 ans (100%), puis dégressif 3 ans",
        "exo_cfe": "5 ans",
        "exo_charges_sociales": "12 mois",
        "conditions": "Implantation dans commune ZRR",
    },
    "BER": {
        "label": "Bassin d'Emploi à Redynamiser",
        "exo_is": "5 ans (100%)",
        "exo_cfe": "5 ans",
        "exo_charges_sociales": "5 ans",
        "conditions": "Zones spécifiques (Lavelanet, Vallée de la Meuse)",
    },
    "QPV": {
        "label": "Quartier Prioritaire de la Politique de la Ville",
        "exo_is": "Non",
        "exo_cfe": "5 ans",
        "exo_charges_sociales": "Non",
        "conditions": "Implantation dans QPV",
    },
    "AFR": {
        "label": "Zone d'Aide à Finalité Régionale",
        "exo_is": "Non",
        "exo_cfe": "Non",
        "exo_charges_sociales": "Non",
        "conditions": "Éligible aux aides directes à l'investissement",
    },
}

_NATIONAL_AIDS = [
    {"name": "CIR (Crédit d'Impôt Recherche)", "type": "fiscal", "amount": "30% des dépenses R&D (< 100M€)", "conditions": "Activité de R&D éligible"},
    {"name": "CII (Crédit d'Impôt Innovation)", "type": "fiscal", "amount": "30% des dépenses (plafond 400K€)", "conditions": "PME, prototype/installation pilote"},
    {"name": "JEI (Jeune Entreprise Innovante)", "type": "fiscal+social", "amount": "Exonération IS 3 ans + charges sociales", "conditions": "< 8 ans, R&D > 15% charges, < 250 salariés"},
    {"name": "BPI Création", "type": "financement", "amount": "Prêt d'honneur 5-50K€", "conditions": "Création/reprise d'entreprise"},
    {"name": "FEDER", "type": "subvention", "amount": "Variable selon programme régional", "conditions": "Projet éligible dans la région"},
    {"name": "French Tech", "type": "label+réseau", "amount": "Accès réseau + programmes (FT120, Next40)", "conditions": "Startup tech en croissance"},
]

_BENCHMARK_IDF_PRICES: dict[str, dict[str, float]] = {
    "Paris 2e-9e": {"bureau_min": 500, "bureau_max": 800, "coworking_poste": 400},
    "Paris 10e-13e": {"bureau_min": 350, "bureau_max": 550, "coworking_poste": 300},
    "Paris 14e-20e": {"bureau_min": 300, "bureau_max": 500, "coworking_poste": 280},
    "La Défense": {"bureau_min": 400, "bureau_max": 700, "coworking_poste": 350},
    "Saint-Denis/Pleyel": {"bureau_min": 200, "bureau_max": 350, "coworking_poste": 250},
    "Montreuil": {"bureau_min": 180, "bureau_max": 300, "coworking_poste": 220},
    "Ivry-sur-Seine": {"bureau_min": 180, "bureau_max": 280, "coworking_poste": 200},
    "Boulogne-Billancourt": {"bureau_min": 350, "bureau_max": 550, "coworking_poste": 320},
    "Lyon Part-Dieu": {"bureau_min": 200, "bureau_max": 350, "coworking_poste": 250},
    "Lyon Confluence": {"bureau_min": 220, "bureau_max": 380, "coworking_poste": 260},
    "Marseille Euroméditerranée": {"bureau_min": 150, "bureau_max": 280, "coworking_poste": 200},
    "Nantes Île de Nantes": {"bureau_min": 160, "bureau_max": 280, "coworking_poste": 220},
    "Bordeaux Euratlantique": {"bureau_min": 180, "bureau_max": 320, "coworking_poste": 240},
    "Toulouse": {"bureau_min": 140, "bureau_max": 250, "coworking_poste": 200},
    "Lille": {"bureau_min": 130, "bureau_max": 240, "coworking_poste": 190},
    "Rennes": {"bureau_min": 130, "bureau_max": 230, "coworking_poste": 180},
    "Strasbourg": {"bureau_min": 120, "bureau_max": 220, "coworking_poste": 180},
    "Montpellier": {"bureau_min": 120, "bureau_max": 220, "coworking_poste": 190},
}


# ── Handlers ─────────────────────────────────────────────────────────────────

async def handle_location_geo_analysis(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Geo-economic analysis of candidate cities/zones."""
    cities = arguments.get("cities", [])
    sector = arguments.get("sector", "tech")
    headcount = arguments.get("headcount", 10)
    priorities = arguments.get("priorities")

    if not cities:
        return [{"type": "text", "text": json.dumps({
            "ok": False, "error": "At least one city/zone is required.",
        })}]

    analyses: list[dict[str, Any]] = []
    for city in cities:
        analysis: dict[str, Any] = {
            "city": city,
            "sector_fit": "HIGH" if sector.lower() in ("tech", "saas", "fintech") else "MEDIUM",
        }

        # Check if we have benchmark data
        price_data = _BENCHMARK_IDF_PRICES.get(city, {})
        if price_data:
            analysis["price_range_sqm"] = {
                "bureau_min": price_data.get("bureau_min", 0),
                "bureau_max": price_data.get("bureau_max", 0),
                "coworking_per_seat": price_data.get("coworking_poste", 0),
            }

        analysis["infrastructure"] = {
            "fiber": True,
            "public_transport": "metro/tram" if any(kw in city.lower() for kw in ("paris", "lyon", "marseille", "lille", "toulouse", "bordeaux", "nantes", "rennes", "strasbourg", "montpellier")) else "bus/TER",
            "tgv_access": any(kw in city.lower() for kw in ("paris", "lyon", "lille", "bordeaux", "nantes", "rennes", "strasbourg", "marseille")),
            "airport_international": any(kw in city.lower() for kw in ("paris", "lyon", "marseille", "nice", "toulouse", "bordeaux", "nantes")),
        }

        analysis["talent_pool"] = {
            "tech_talent_density": "HIGH" if any(kw in city.lower() for kw in ("paris", "lyon", "nantes", "toulouse", "bordeaux", "montpellier")) else "MEDIUM",
            "universities_nearby": True,
            "estimated_salary_index": 1.0 if "paris" not in city.lower() else 1.3,
        }

        analysis["ecosystem"] = {
            "incubators_nearby": True,
            "coworking_spaces": True,
            "tech_meetups": "frequent" if any(kw in city.lower() for kw in ("paris", "lyon", "nantes", "toulouse")) else "occasional",
        }

        analyses.append(analysis)

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "cities_analyzed": len(analyses),
        "sector": sector,
        "headcount": headcount,
        "analyses": analyses,
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Analyse géo-économique par IA — données indicatives, vérification terrain requise.",
    }, ensure_ascii=False, indent=2)}]


async def handle_location_real_estate(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Real estate market intelligence."""
    zone = arguments.get("zone", "Île-de-France")
    property_type = arguments.get("property_type", "bureau")
    surface_min = arguments.get("surface_min", 100)
    surface_max = arguments.get("surface_max")
    budget_max = arguments.get("budget_max")

    property_label = _PROPERTY_TYPES.get(property_type, property_type)

    # Find matching benchmark zones
    matching_zones: list[dict[str, Any]] = []
    for zone_name, prices in _BENCHMARK_IDF_PRICES.items():
        if zone.lower() in zone_name.lower() or zone_name.lower() in zone.lower() or zone.lower() in ("île-de-france", "ile-de-france", "idf", "france"):
            estimated_monthly = prices.get("bureau_min", 200) * surface_min / 12
            entry: dict[str, Any] = {
                "zone": zone_name,
                "price_sqm_year": {"min": prices.get("bureau_min", 0), "max": prices.get("bureau_max", 0)},
                "coworking_per_seat_month": prices.get("coworking_poste", 0),
                "estimated_monthly_rent": round(estimated_monthly),
            }

            if budget_max and estimated_monthly > budget_max:
                entry["within_budget"] = False
            else:
                entry["within_budget"] = True

            matching_zones.append(entry)

    # Sort by price
    matching_zones.sort(key=lambda x: x["price_sqm_year"]["min"])

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "search_criteria": {
            "zone": zone,
            "property_type": property_label,
            "surface_min_sqm": surface_min,
            "surface_max_sqm": surface_max,
            "budget_max_monthly": budget_max,
        },
        "zones_found": len(matching_zones),
        "results": matching_zones,
        "market_trend": "stable" if property_type == "bureau" else "hausse",
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Données immobilières indicatives — négociation et visite requises.",
    }, ensure_ascii=False, indent=2)}]


async def handle_location_site_score(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Multi-criteria site scoring."""
    sites = arguments.get("sites", [])
    custom_scores = arguments.get("scores", {})
    custom_weights = arguments.get("weights", {})

    if not sites:
        return [{"type": "text", "text": json.dumps({
            "ok": False, "error": "At least one site is required.",
        })}]

    # Build weights
    weights: dict[str, float] = {}
    total_weight = 0
    for criterion, data in _SCORING_CRITERIA.items():
        w = custom_weights.get(criterion, data["default_weight"])
        weights[criterion] = w
        total_weight += w

    # Score each site
    site_results: list[dict[str, Any]] = []
    for site in sites:
        site_custom = custom_scores.get(site, {})
        criteria_scores: dict[str, Any] = {}
        weighted_total = 0.0

        for criterion, data in _SCORING_CRITERIA.items():
            raw_score = site_custom.get(criterion, 5)  # default 5/10 if not provided
            weight = weights[criterion]
            weighted = raw_score * weight / max(total_weight, 1) * 10
            criteria_scores[criterion] = {
                "label": data["label"],
                "raw_score": raw_score,
                "weight": weight,
                "weighted_score": round(weighted, 2),
            }
            weighted_total += weighted

        site_results.append({
            "site": site,
            "total_score": round(weighted_total, 1),
            "criteria": criteria_scores,
        })

    # Sort by total score
    site_results.sort(key=lambda x: x["total_score"], reverse=True)

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "sites_scored": len(site_results),
        "criteria_used": len(_SCORING_CRITERIA),
        "results": site_results,
        "recommended": site_results[0]["site"] if site_results else None,
        "recommended_score": site_results[0]["total_score"] if site_results else None,
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Scoring par IA — visite terrain et validation requises.",
    }, ensure_ascii=False, indent=2)}]


async def handle_location_incentives(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Tax incentives and aid programs by territory."""
    zone = arguments.get("zone", "")
    company_type = arguments.get("company_type", "startup")
    headcount = arguments.get("headcount", 10)
    sector = arguments.get("sector", "tech")

    # Check applicable tax zones
    applicable_zones: list[dict[str, Any]] = []
    for zone_code, zone_data in _TAX_ZONES.items():
        applicable_zones.append({
            "zone_code": zone_code,
            "label": zone_data["label"],
            "exo_is": zone_data["exo_is"],
            "exo_cfe": zone_data["exo_cfe"],
            "exo_charges": zone_data["exo_charges_sociales"],
            "conditions": zone_data["conditions"],
            "relevance": "Check eligibility for: " + zone,
        })

    # National aids
    applicable_aids: list[dict[str, Any]] = []
    for aid in _NATIONAL_AIDS:
        relevant = True
        if "JEI" in aid["name"] and headcount > 250:
            relevant = False
        if "CII" in aid["name"] and company_type != "startup":
            relevant = False

        if relevant:
            applicable_aids.append(aid)

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "zone_searched": zone,
        "company_profile": {
            "type": company_type,
            "headcount": headcount,
            "sector": sector,
        },
        "tax_zones": applicable_zones,
        "national_aids": applicable_aids,
        "total_incentive_programs": len(applicable_zones) + len(applicable_aids),
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Données fiscales indicatives — vérification auprès des organismes requise.",
    }, ensure_ascii=False, indent=2)}]


async def handle_location_tco_simulate(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Total Cost of Occupation simulation."""
    sites = arguments.get("sites", [])
    surface = arguments.get("surface", 200)
    horizon_years = arguments.get("horizon_years", 3)
    headcount = arguments.get("headcount", 10)
    annual_rent_increase = arguments.get("annual_rent_increase", 0.03)

    if not sites:
        return [{"type": "text", "text": json.dumps({
            "ok": False, "error": "At least one site is required.",
        })}]

    simulations: list[dict[str, Any]] = []
    for site in sites:
        price_data = _BENCHMARK_IDF_PRICES.get(site, {})
        avg_price_sqm = (price_data.get("bureau_min", 200) + price_data.get("bureau_max", 400)) / 2

        yearly_projections: list[dict[str, Any]] = []
        total_tco = 0.0

        for year in range(1, horizon_years + 1):
            adjusted_price = avg_price_sqm * ((1 + annual_rent_increase) ** (year - 1))
            annual_rent = adjusted_price * surface
            charges = annual_rent * 0.15  # ~15% charges
            cfe = annual_rent * 0.02      # ~2% CFE estimate
            insurance = surface * 5       # ~5€/m²/an
            maintenance = surface * 10    # ~10€/m²/an
            total_year = annual_rent + charges + cfe + insurance + maintenance

            yearly_projections.append({
                "year": year,
                "rent": round(annual_rent),
                "charges": round(charges),
                "cfe": round(cfe),
                "insurance": round(insurance),
                "maintenance": round(maintenance),
                "total": round(total_year),
            })
            total_tco += total_year

        simulations.append({
            "site": site,
            "surface_sqm": surface,
            "price_sqm_year": round(avg_price_sqm),
            "yearly_projections": yearly_projections,
            "total_tco": round(total_tco),
            "monthly_average": round(total_tco / (horizon_years * 12)),
            "cost_per_employee_month": round(total_tco / (horizon_years * 12 * max(headcount, 1))),
        })

    # Sort by TCO
    simulations.sort(key=lambda x: x["total_tco"])

    cheapest = simulations[0] if simulations else None
    most_expensive = simulations[-1] if simulations else None
    savings = (most_expensive["total_tco"] - cheapest["total_tco"]) if cheapest and most_expensive and len(simulations) > 1 else 0

    return [{"type": "text", "text": json.dumps({
        "ok": True,
        "sites_compared": len(simulations),
        "horizon_years": horizon_years,
        "surface_sqm": surface,
        "simulations": simulations,
        "recommended": cheapest["site"] if cheapest else None,
        "potential_savings": round(savings),
        "timestamp": datetime.now(UTC).isoformat(),
        "disclaimer": "⚠️ Simulation TCO par IA — devis réels et négociation requises.",
    }, ensure_ascii=False, indent=2)}]


# ── Tool definitions ─────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_location_geo_analysis",
        "title": "Location — Geo-Economic Analysis",
        "description": "Geo-economic analysis of candidate cities — talent pools, transport, ecosystem, infrastructure, quality of life. Compares multiple zones.",
        "category": "location_strategy",
        "annotations": {"title": "Location — Geo-Economic Analysis", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "analyses": {"type": "array"}}},
        "handler": handle_location_geo_analysis,
        "inputSchema": {
            "type": "object",
            "properties": {
                "cities": {"type": "array", "items": {"type": "string"}, "description": "List of cities/zones to analyze"},
                "sector": {"type": "string", "description": "Business sector"},
                "headcount": {"type": "integer", "description": "Current/planned headcount"},
                "priorities": {"type": "array", "items": {"type": "string"}, "description": "Priority criteria"},
            },
            "required": ["cities"],
        },
    },
    {
        "name": "openclaw_location_real_estate",
        "title": "Location — Real Estate Intelligence",
        "description": "Real estate market intelligence — availability, pricing per sqm, coworking rates, trends by zone. Filters by budget and surface.",
        "category": "location_strategy",
        "annotations": {"title": "Location — Real Estate Intelligence", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "zones_found": {"type": "integer"}, "results": {"type": "array"}}},
        "handler": handle_location_real_estate,
        "inputSchema": {
            "type": "object",
            "properties": {
                "zone": {"type": "string", "description": "Zone/region to search (e.g., 'Île-de-France', 'Lyon')"},
                "property_type": {"type": "string", "description": "Type: bureau, coworking, entrepot, commerce, mixte"},
                "surface_min": {"type": "integer", "description": "Minimum surface in sqm"},
                "surface_max": {"type": "integer", "description": "Maximum surface in sqm"},
                "budget_max": {"type": "number", "description": "Maximum monthly budget (€)"},
            },
        },
    },
    {
        "name": "openclaw_location_site_score",
        "title": "Location — Site Scoring",
        "description": "Multi-criteria site scoring with 20+ weighted criteria. Compares sites on transport, talent, cost, ecosystem, and more. Outputs ranked matrix.",
        "category": "location_strategy",
        "annotations": {"title": "Location — Site Scoring", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "recommended": {"type": "string"}, "results": {"type": "array"}}},
        "handler": handle_location_site_score,
        "inputSchema": {
            "type": "object",
            "properties": {
                "sites": {"type": "array", "items": {"type": "string"}, "description": "List of sites to score"},
                "scores": {"type": "object", "description": "Custom scores per site: {site: {criterion: score(1-10)}}"},
                "weights": {"type": "object", "description": "Custom weights per criterion: {criterion: weight}"},
            },
            "required": ["sites"],
        },
    },
    {
        "name": "openclaw_location_incentives",
        "title": "Location — Tax Incentives",
        "description": "Tax incentives and aid programs by territory — ZFU, ZRR, BER, CIR, JEI, BPI, FEDER. Matches company profile to available programs.",
        "category": "location_strategy",
        "annotations": {"title": "Location — Tax Incentives", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "tax_zones": {"type": "array"}, "national_aids": {"type": "array"}}},
        "handler": handle_location_incentives,
        "inputSchema": {
            "type": "object",
            "properties": {
                "zone": {"type": "string", "description": "Zone/city to check for incentives"},
                "company_type": {"type": "string", "description": "Company type: startup, scaleup, enterprise"},
                "headcount": {"type": "integer", "description": "Number of employees"},
                "sector": {"type": "string", "description": "Business sector"},
            },
        },
    },
    {
        "name": "openclaw_location_tco_simulate",
        "title": "Location — TCO Simulation",
        "description": "Total Cost of Occupation simulation over 3-5 years. Includes rent, charges, CFE, insurance, maintenance. Compares multiple sites.",
        "category": "location_strategy",
        "annotations": {"title": "Location — TCO Simulation", "readOnlyHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}, "recommended": {"type": "string"}, "simulations": {"type": "array"}}},
        "handler": handle_location_tco_simulate,
        "inputSchema": {
            "type": "object",
            "properties": {
                "sites": {"type": "array", "items": {"type": "string"}, "description": "List of sites to compare"},
                "surface": {"type": "integer", "description": "Surface in sqm"},
                "horizon_years": {"type": "integer", "description": "Simulation horizon (1-10 years)"},
                "headcount": {"type": "integer", "description": "Number of employees (for per-capita cost)"},
                "annual_rent_increase": {"type": "number", "description": "Expected annual rent increase (0.03 = 3%)"},
            },
            "required": ["sites"],
        },
    },
]
