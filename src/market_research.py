"""
market_research.py — Market Research & Competitive Intelligence tools

Implements 6 tools for the Market Research department:
  - Competitive landscape analysis (feature matrix, SWOT, positioning)
  - Market sizing (TAM/SAM/SOM, top-down + bottom-up)
  - Financial benchmarking (unit economics, pricing, revenue)
  - Web research & OSINT (structured multi-source intelligence)
  - Professional report generation (Markdown, cross-department accessible)
  - Competitive monitoring (continuous tracking of competitor moves)

Tools exposed (6):
  openclaw_market_competitive_analysis   — competitive landscape + SWOT + positioning
  openclaw_market_sizing                 — TAM/SAM/SOM with confidence scoring
  openclaw_market_financial_benchmark    — unit economics + pricing analysis
  openclaw_market_web_research           — structured web OSINT research
  openclaw_market_report_generate        — professional Markdown report generation
  openclaw_market_research_monitor       — continuous competitive monitoring
"""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

OUTPUT_DIR: str = os.getenv(
    "MARKET_RESEARCH_OUTPUT_DIR",
    os.path.expanduser("~/.openclaw/market-research"),
)

_CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}

_SWOT_CATEGORIES = ("strengths", "weaknesses", "opportunities", "threats")

_DEFAULT_CRITERIA = [
    "pricing",
    "target_market",
    "key_features",
    "market_share",
    "funding",
    "headcount",
    "founded",
    "geography",
    "tech_stack",
    "integrations",
    "nps_score",
    "growth_rate",
]

_FINANCIAL_METRICS = {
    "CAC": "Customer Acquisition Cost",
    "LTV": "Lifetime Value",
    "LTV_CAC": "LTV / CAC Ratio",
    "ARPU": "Average Revenue Per User",
    "churn": "Monthly Churn Rate",
    "gross_margin": "Gross Margin %",
    "burn_rate": "Monthly Burn Rate",
    "runway": "Runway (months)",
    "payback_period": "Payback Period (months)",
    "arr": "Annual Recurring Revenue",
    "mrr": "Monthly Recurring Revenue",
    "net_revenue_retention": "Net Revenue Retention %",
}

_OSINT_SOURCES = {
    "crunchbase": "Crunchbase — company data, funding, investors",
    "linkedin": "LinkedIn — headcount, growth, hiring trends",
    "g2": "G2 — user reviews, ratings, feature comparison",
    "capterra": "Capterra — software reviews and comparison",
    "trustpilot": "Trustpilot — customer reviews and NPS proxy",
    "glassdoor": "Glassdoor — employer reviews, culture signals",
    "builtwith": "BuiltWith — technology stack detection",
    "similarweb": "SimilarWeb — web traffic and analytics",
    "sec_filings": "SEC/AMF — public financial filings",
    "patents": "Patent databases — intellectual property",
    "github": "GitHub — open source activity, tech choices",
    "twitter": "Twitter/X — sentiment, announcements",
    "news": "News aggregators — press coverage, partnerships",
    "statista": "Statista — market statistics and reports",
    "app_store": "App Store / Play Store — app reviews and ratings",
}

# ── In-memory monitoring store ───────────────────────────────────────────────

_MONITOR_WATCHLIST: dict[str, dict[str, Any]] = {}

# ── In-memory research cache (for report generation) ────────────────────────

_RESEARCH_CACHE: dict[str, dict[str, Any]] = {}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _confidence_label(level: str) -> str:
    """Return emoji + label for confidence level."""
    mapping = {"HIGH": "🟢 HIGH", "MEDIUM": "🟡 MEDIUM", "LOW": "🔴 LOW"}
    return mapping.get(level.upper(), f"⚪ {level}")


def _ensure_output_dir() -> Path:
    p = Path(OUTPUT_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _save_to_cache(key: str, data: dict[str, Any]) -> None:
    """Save research data to cache for report generation."""
    _RESEARCH_CACHE[key] = {**data, "_cached_at": time.time()}


def _ai_footer() -> str:
    return (
        "\n\n---\n"
        f"_📊 Généré par Market Research Department · {_timestamp()}_\n"
        "_⚠️ Étude de marché générée par IA — validation par un analyste senior "
        "requise avant décision stratégique._"
    )


# ── Tool: openclaw_market_competitive_analysis ───────────────────────────────

def openclaw_market_competitive_analysis(
    sector: str,
    competitors: list[str] | None = None,
    geography: str | None = None,
    criteria: list[str] | None = None,
    include_swot: bool = True,
    include_positioning: bool = True,
    our_product: str | None = None,
) -> dict[str, Any]:
    """
    Produce a structured competitive landscape analysis.

    Returns a feature matrix, optional SWOT per competitor,
    and a positioning map framework.
    """
    used_criteria = criteria or _DEFAULT_CRITERIA
    comp_list = competitors or []
    geo = geography or "Global"
    ts = _timestamp()

    # Build feature matrix template
    feature_matrix: list[dict[str, Any]] = []
    for comp in comp_list:
        row: dict[str, Any] = {"competitor": comp}
        for c in used_criteria:
            row[c] = f"[À renseigner — {c}]"
        feature_matrix.append(row)

    # Add our product row if specified
    if our_product:
        our_row: dict[str, Any] = {"competitor": f"✅ {our_product} (nous)"}
        for c in used_criteria:
            our_row[c] = f"[À renseigner — {c}]"
        feature_matrix.insert(0, our_row)

    # SWOT templates
    swot_analysis: dict[str, dict[str, list[str]]] = {}
    if include_swot:
        for comp in comp_list:
            swot_analysis[comp] = {
                cat: [f"[{cat.upper()} — à compléter par recherche]"]
                for cat in _SWOT_CATEGORIES
            }

    # Positioning map framework
    positioning: dict[str, Any] = {}
    if include_positioning:
        positioning = {
            "axes": {
                "x": {"label": "Prix (bas → haut)", "min": "Low-cost", "max": "Premium"},
                "y": {"label": "Fonctionnalités (basic → avancé)", "min": "Simple", "max": "Enterprise"},
            },
            "quadrants": {
                "top_left": "Challengers (prix bas, features riches)",
                "top_right": "Leaders (premium, features riches)",
                "bottom_left": "Niche (prix bas, features limitées)",
                "bottom_right": "Spécialisés (premium, features ciblées)",
            },
            "competitors_placement": {
                comp: {"x": "[0-10]", "y": "[0-10]", "quadrant": "[à déterminer]"}
                for comp in comp_list
            },
        }

    result = {
        "ok": True,
        "sector": sector,
        "geography": geo,
        "timestamp": ts,
        "competitors_count": len(comp_list),
        "competitors": comp_list,
        "criteria": used_criteria,
        "feature_matrix": feature_matrix,
        "swot_analysis": swot_analysis if include_swot else None,
        "positioning_map": positioning if include_positioning else None,
        "methodology": {
            "approach": "Structured competitive analysis framework",
            "data_sources": "Public sources — to be enriched via openclaw_market_web_research",
            "confidence": "LOW — template generated, requires data enrichment",
        },
        "next_steps": [
            "Enrichir la feature matrix via openclaw_market_web_research",
            "Compléter les SWOT avec des données primaires",
            "Valider le positionnement avec le département Commercial",
            "Générer les battlecards individuelles par concurrent",
        ],
        "ai_disclaimer": "⚠️ Étude de marché générée par IA — validation par un analyste senior requise.",
    }

    _save_to_cache(f"competitive_{sector}", result)
    return result


# ── Tool: openclaw_market_sizing ─────────────────────────────────────────────

def openclaw_market_sizing(
    sector: str,
    geography: str | None = None,
    target_segment: str | None = None,
    horizon_years: int = 5,
    known_data: dict[str, Any] | None = None,
    approach: str = "both",
) -> dict[str, Any]:
    """
    TAM/SAM/SOM market sizing with top-down and bottom-up approaches.

    Args:
        sector: Target market sector
        geography: Geographic scope (default: Global)
        target_segment: Specific segment within sector
        horizon_years: Forecast horizon in years (default: 5)
        known_data: Pre-existing data points (market size, growth rate, etc.)
        approach: "top_down", "bottom_up", or "both"
    """
    geo = geography or "Global"
    segment = target_segment or "All segments"
    data = known_data or {}
    ts = _timestamp()

    # Build sizing framework
    top_down: dict[str, Any] | None = None
    bottom_up: dict[str, Any] | None = None

    if approach in ("top_down", "both"):
        top_down = {
            "description": "Top-down: partir du marché global → filtrer par segment",
            "steps": [
                {"step": 1, "action": "Total market size (rapports sectoriels)", "value": data.get("total_market", "[À renseigner]"), "source": data.get("total_market_source", "[Source requise]"), "confidence": "MEDIUM"},
                {"step": 2, "action": f"Filter by geography ({geo})", "value": data.get("geo_share", "[% du marché global]"), "source": "[Source requise]", "confidence": "MEDIUM"},
                {"step": 3, "action": f"Filter by segment ({segment})", "value": data.get("segment_share", "[% du marché géo]"), "source": "[Source requise]", "confidence": "LOW"},
                {"step": 4, "action": "Realistic capture rate (SOM)", "value": data.get("capture_rate", "2-5%"), "source": "Industry benchmark", "confidence": "LOW"},
            ],
            "tam": data.get("tam", "[À calculer]"),
            "sam": data.get("sam", "[À calculer]"),
            "som": data.get("som", "[À calculer]"),
        }

    if approach in ("bottom_up", "both"):
        bottom_up = {
            "description": "Bottom-up: partir des unit economics → projeter",
            "steps": [
                {"step": 1, "action": "Target customers count", "value": data.get("target_customers", "[À renseigner]"), "source": "[Source requise]", "confidence": "MEDIUM"},
                {"step": 2, "action": "Average deal size / ARPU", "value": data.get("arpu", "[À renseigner]"), "source": "[Source requise]", "confidence": "MEDIUM"},
                {"step": 3, "action": "Conversion rate (pipeline → closed)", "value": data.get("conversion_rate", "2-5%"), "source": "Industry benchmark", "confidence": "LOW"},
                {"step": 4, "action": "Year 1 revenue projection", "value": data.get("year1_revenue", "[À calculer]"), "source": "Calculation", "confidence": "LOW"},
            ],
            "year_projections": {
                f"year_{y}": data.get(f"year_{y}", "[À projeter]")
                for y in range(1, horizon_years + 1)
            },
        }

    # Growth analysis
    growth_analysis = {
        "cagr": data.get("cagr", "[CAGR sectoriel — source requise]"),
        "growth_drivers": [
            "Digitalisation du secteur",
            "Adoption cloud / SaaS",
            "Évolution réglementaire",
            "Consolidation marché (M&A)",
        ],
        "growth_inhibitors": [
            "Concurrence intense",
            "Maturité du marché",
            "Coûts de switching élevés",
            "Incertitude macroéconomique",
        ],
    }

    result = {
        "ok": True,
        "sector": sector,
        "geography": geo,
        "target_segment": segment,
        "horizon_years": horizon_years,
        "timestamp": ts,
        "approach": approach,
        "top_down": top_down,
        "bottom_up": bottom_up,
        "growth_analysis": growth_analysis,
        "methodology": {
            "triangulation": "Cross-reference top-down and bottom-up for validation",
            "sources_needed": [
                "Rapport sectoriel (Statista, Gartner, IDC, Forrester)",
                "Données démographiques / économiques (INSEE, Eurostat)",
                "Données concurrents (Crunchbase, SEC filings)",
                "Enquêtes terrain / interviews clients",
            ],
            "confidence": "LOW — framework generated, requires data enrichment",
        },
        "ai_disclaimer": "⚠️ Estimation de marché générée par IA — à valider avec des données primaires.",
    }

    _save_to_cache(f"sizing_{sector}", result)
    return result


# ── Tool: openclaw_market_financial_benchmark ────────────────────────────────

def openclaw_market_financial_benchmark(
    sector: str,
    metrics: list[str] | None = None,
    competitors: list[str] | None = None,
    our_data: dict[str, Any] | None = None,
    include_pricing: bool = True,
) -> dict[str, Any]:
    """
    Financial benchmarking — unit economics, pricing analysis, revenue comparisons.

    Args:
        sector: Target market sector
        metrics: Financial metrics to benchmark (default: all standard metrics)
        competitors: Competitor names to include
        our_data: Our company's financial data for comparison
        include_pricing: Include pricing strategy analysis
    """
    used_metrics = metrics or list(_FINANCIAL_METRICS.keys())
    comp_list = competitors or []
    ts = _timestamp()

    # Build benchmark table
    benchmark_table: list[dict[str, Any]] = []
    for metric in used_metrics:
        label = _FINANCIAL_METRICS.get(metric, metric)
        row: dict[str, Any] = {
            "metric": metric,
            "label": label,
            "our_value": "[À renseigner]",
            "market_average": "[Benchmark sectoriel requis]",
            "top_performer": "[Top quartile]",
            "source": "[Source requise]",
            "confidence": "LOW",
        }
        if our_data and metric in our_data:
            row["our_value"] = our_data[metric]
            row["confidence"] = "HIGH"
        benchmark_table.append(row)

    # Per-competitor financial profiles
    competitor_profiles: dict[str, dict[str, Any]] = {}
    for comp in comp_list:
        competitor_profiles[comp] = {
            "estimated_arr": "[Public data or estimate]",
            "funding_total": "[Crunchbase]",
            "last_round": "[Crunchbase]",
            "headcount": "[LinkedIn estimate]",
            "revenue_per_employee": "[Calculation]",
            "pricing_model": "[Public pricing page]",
            "price_range": "[Min-Max per user/month]",
        }

    # Pricing analysis
    pricing_analysis: dict[str, Any] | None = None
    if include_pricing:
        pricing_analysis = {
            "market_pricing_range": {
                "low": "[Pricing floor — entry-level]",
                "median": "[Market median]",
                "high": "[Premium tier]",
            },
            "pricing_models_observed": [
                "Per user / per seat",
                "Usage-based (API calls, storage)",
                "Flat rate tiers",
                "Freemium + premium upsell",
                "Enterprise custom pricing",
            ],
            "recommended_strategy": "[Based on positioning — requires competitive_analysis data]",
            "price_sensitivity_factors": [
                "Taille de l'entreprise cible",
                "Valeur perçue vs alternatives",
                "Coût de changement (switching cost)",
                "Budget IT moyen du segment cible",
            ],
        }

    result = {
        "ok": True,
        "sector": sector,
        "timestamp": ts,
        "metrics_analyzed": used_metrics,
        "benchmark_table": benchmark_table,
        "competitor_profiles": competitor_profiles,
        "pricing_analysis": pricing_analysis,
        "health_indicators": {
            "unit_economics_verdict": "[HEALTHY / WARNING / CRITICAL — requires our_data]",
            "key_ratios": {
                "ltv_cac": {"target": ">3x", "our_value": our_data.get("LTV_CAC", "[N/A]") if our_data else "[N/A]"},
                "payback": {"target": "<12 months", "our_value": our_data.get("payback_period", "[N/A]") if our_data else "[N/A]"},
                "gross_margin": {"target": ">70%", "our_value": our_data.get("gross_margin", "[N/A]") if our_data else "[N/A]"},
                "net_retention": {"target": ">100%", "our_value": our_data.get("net_revenue_retention", "[N/A]") if our_data else "[N/A]"},
            },
        },
        "methodology": {
            "data_sources": "Public filings, Crunchbase, industry reports, pricing pages",
            "confidence": "LOW — most competitor financials are estimated unless publicly traded",
        },
        "ai_disclaimer": "⚠️ Benchmark financier généré par IA — ne remplace pas un expert-comptable certifié.",
    }

    _save_to_cache(f"financial_{sector}", result)
    return result


# ── Tool: openclaw_market_web_research ───────────────────────────────────────

def openclaw_market_web_research(
    query: str,
    sources: list[str] | None = None,
    competitor: str | None = None,
    max_results: int = 10,
) -> dict[str, Any]:
    """
    Structured web research and OSINT intelligence gathering.

    Args:
        query: Research query string
        sources: Specific OSINT sources to prioritize
        competitor: Specific competitor to research
        max_results: Maximum number of research findings
    """
    used_sources = sources or ["news", "crunchbase", "linkedin"]
    ts = _timestamp()

    # Build research plan
    research_plan: list[dict[str, Any]] = []
    for src in used_sources:
        src_lower = src.lower()
        desc = _OSINT_SOURCES.get(src_lower, f"{src} — custom source")
        research_plan.append({
            "source": src,
            "description": desc,
            "query": f"{query}" + (f" {competitor}" if competitor else ""),
            "status": "planned",
            "findings": [],
        })

    # Build structured output
    result = {
        "ok": True,
        "query": query,
        "competitor": competitor,
        "timestamp": ts,
        "sources_planned": len(research_plan),
        "research_plan": research_plan,
        "osint_sources_available": {
            k: v for k, v in _OSINT_SOURCES.items()
            if k in [s.lower() for s in used_sources]
        },
        "search_queries_suggested": [
            f'"{query}" market size {datetime.now(UTC).year}',
            f'"{query}" competitive landscape',
            f'"{query}" pricing comparison',
            f'"{competitor} funding rounds" site:crunchbase.com' if competitor else None,
            f'"{competitor}" headcount linkedin' if competitor else None,
            f'"{competitor}" reviews site:g2.com' if competitor else None,
        ],
        "methodology": {
            "approach": "Structured OSINT with source triangulation",
            "min_sources_per_claim": 3,
            "confidence_scoring": {
                "HIGH": "Public verified data (SEC filings, official announcements)",
                "MEDIUM": "Cross-referenced estimates (2+ independent sources)",
                "LOW": "Single source or extrapolation",
            },
        },
        "ai_disclaimer": "⚠️ Recherche web générée par IA — vérifier chaque source avant utilisation.",
    }

    # Filter out None suggestions
    result["search_queries_suggested"] = [
        q for q in result["search_queries_suggested"] if q is not None
    ]

    _save_to_cache(f"research_{query[:50]}", result)
    return result


# ── Tool: openclaw_market_report_generate ────────────────────────────────────

_REPORT_SECTIONS = {
    "executive_summary": "## 1. Executive Summary",
    "methodology": "## 2. Méthodologie et Sources",
    "market_overview": "## 3. Market Overview",
    "competitive_landscape": "## 4. Paysage Concurrentiel",
    "financial_analysis": "## 5. Analyse Financière Comparative",
    "segmentation": "## 6. Segmentation & Cibles",
    "positioning": "## 7. Positionnement Stratégique",
    "recommendations": "## 8. Recommandations",
    "appendices": "## 9. Annexes",
}


def openclaw_market_report_generate(
    title: str,
    sections: list[str] | None = None,
    data: dict[str, Any] | None = None,
    output_path: str | None = None,
    language: str = "fr",
    include_toc: bool = True,
) -> dict[str, Any]:
    """
    Generate a complete professional market research report in Markdown.

    The report is structured to be readable by every department:
    CEO (executive summary), CFO (financial analysis), CTO (tech landscape),
    Marketing (positioning), Commercial (competitive landscape), etc.

    Args:
        title: Report title
        sections: Sections to include (default: all)
        data: Pre-collected research data to incorporate
        output_path: File path for output (default: auto-generated)
        language: Report language — "fr" or "en"
        include_toc: Include table of contents
    """
    used_sections = sections or list(_REPORT_SECTIONS.keys())
    ts = _timestamp()
    report_data = data or {}

    # Pull from cache if available
    for key, cached in _RESEARCH_CACHE.items():
        if key not in report_data:
            report_data[key] = cached

    # Build Markdown report
    lines: list[str] = []

    # Header
    lines.append(f"# 📊 {title}")
    lines.append("")
    lines.append("> ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.")
    lines.append("")
    lines.append(f"**Date :** {datetime.now(UTC).strftime('%Y-%m-%d')}")
    lines.append("**Département :** Market Research")
    lines.append("**Analyste :** Élise Montblanc (Market Research Director, IA)")
    lines.append("**Confiance globale :** 🟡 MEDIUM — à affiner avec données primaires")
    lines.append(f"**Langue :** {'Français' if language == 'fr' else 'English'}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Table of contents
    if include_toc:
        lines.append("## Table des matières")
        lines.append("")
        for i, sec_key in enumerate(used_sections, 1):
            sec_title = _REPORT_SECTIONS.get(sec_key, f"## {i}. {sec_key}")
            # Extract just the title text
            clean_title = sec_title.replace("## ", "").strip()
            lines.append(f"{i}. [{clean_title}](#{sec_key})")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Generate each section
    for sec_key in used_sections:
        sec_header = _REPORT_SECTIONS.get(sec_key, f"## {sec_key}")
        lines.append(f"<a id=\"{sec_key}\"></a>")
        lines.append("")
        lines.append(sec_header)
        lines.append("")

        if sec_key == "executive_summary":
            lines.append("**Points clés :**")
            lines.append("")
            lines.append("1. [Opportunité marché — chiffre clé]")
            lines.append("2. [Position concurrentielle — verdict]")
            lines.append("3. [Recommandation principale — action]")
            lines.append("4. [Risque principal — mitigation]")
            lines.append("5. [Prochaine étape — délai]")
            lines.append("")
            lines.append("> 💡 **Décision requise :** [Question pour le CEO]")
            lines.append("")

        elif sec_key == "methodology":
            lines.append("| Source | Type | Confiance | Date dernière vérification |")
            lines.append("|--------|------|-----------|---------------------------|")
            lines.append("| [Source 1] | Primaire / Secondaire | HIGH/MEDIUM/LOW | YYYY-MM-DD |")
            lines.append("| [Source 2] | Primaire / Secondaire | HIGH/MEDIUM/LOW | YYYY-MM-DD |")
            lines.append("")
            lines.append("**Approche :** Triangulation multi-sources (minimum 3 sources par donnée clé)")
            lines.append("")

        elif sec_key == "market_overview":
            lines.append("### TAM / SAM / SOM")
            lines.append("")
            lines.append("| Métrique | Valeur | Source | Confiance |")
            lines.append("|----------|--------|--------|-----------|")
            lines.append("| TAM (Total Addressable Market) | [€___M] | [Source] | MEDIUM |")
            lines.append("| SAM (Serviceable Addressable Market) | [€___M] | [Source] | MEDIUM |")
            lines.append("| SOM (Serviceable Obtainable Market) | [€___M] | [Calcul interne] | LOW |")
            lines.append("")
            lines.append("### Tendances clés")
            lines.append("")
            lines.append("1. **[Tendance 1]** — [Impact et horizon]")
            lines.append("2. **[Tendance 2]** — [Impact et horizon]")
            lines.append("3. **[Tendance 3]** — [Impact et horizon]")
            lines.append("")
            lines.append("### Croissance")
            lines.append("")
            lines.append("- **CAGR sectoriel :** [___%] (source: [___])")
            lines.append("- **Drivers :** [liste]")
            lines.append("- **Freins :** [liste]")
            lines.append("")

        elif sec_key == "competitive_landscape":
            lines.append("### Matrice concurrentielle")
            lines.append("")
            lines.append("| Critère | Notre produit | Concurrent A | Concurrent B | Concurrent C |")
            lines.append("|---------|:------------:|:------------:|:------------:|:------------:|")
            lines.append("| Prix | [___] | [___] | [___] | [___] |")
            lines.append("| Cible | [___] | [___] | [___] | [___] |")
            lines.append("| Feature clé 1 | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ |")
            lines.append("| Feature clé 2 | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ |")
            lines.append("| Market share | [___] | [___] | [___] | [___] |")
            lines.append("| Funding | [___] | [___] | [___] | [___] |")
            lines.append("| NPS | [___] | [___] | [___] | [___] |")
            lines.append("")
            lines.append("### SWOT — [Concurrent principal]")
            lines.append("")
            lines.append("| Forces | Faiblesses |")
            lines.append("|--------|------------|")
            lines.append("| [___] | [___] |")
            lines.append("")
            lines.append("| Opportunités | Menaces |")
            lines.append("|-------------|---------|")
            lines.append("| [___] | [___] |")
            lines.append("")
            lines.append("### Carte de positionnement")
            lines.append("")
            lines.append("```")
            lines.append("        Prix élevé")
            lines.append("            │")
            lines.append("   Niche    │   Leaders")
            lines.append("            │")
            lines.append("────────────┼────────────── Features")
            lines.append("            │                avancées")
            lines.append("  Entrants  │  Challengers")
            lines.append("            │")
            lines.append("       Prix bas")
            lines.append("```")
            lines.append("")

        elif sec_key == "financial_analysis":
            lines.append("### Unit Economics comparatifs")
            lines.append("")
            lines.append("| Métrique | Nous | Marché moyen | Top performer | Verdict |")
            lines.append("|----------|:----:|:------------:|:-------------:|:-------:|")
            lines.append("| CAC | [€___] | [€___] | [€___] | 🟢/🟡/🔴 |")
            lines.append("| LTV | [€___] | [€___] | [€___] | 🟢/🟡/🔴 |")
            lines.append("| LTV/CAC | [___x] | [___x] | [___x] | 🟢/🟡/🔴 |")
            lines.append("| ARPU | [€___] | [€___] | [€___] | 🟢/🟡/🔴 |")
            lines.append("| Churn mensuel | [___%] | [___%] | [___%] | 🟢/🟡/🔴 |")
            lines.append("| Marge brute | [___%] | [___%] | [___%] | 🟢/🟡/🔴 |")
            lines.append("| Payback period | [___m] | [___m] | [___m] | 🟢/🟡/🔴 |")
            lines.append("")
            lines.append("### Analyse pricing")
            lines.append("")
            lines.append("| Tier | Notre prix | Marché min | Marché median | Marché max |")
            lines.append("|------|:----------:|:----------:|:-------------:|:----------:|")
            lines.append("| Starter | [€___/mois] | [€___] | [€___] | [€___] |")
            lines.append("| Pro | [€___/mois] | [€___] | [€___] | [€___] |")
            lines.append("| Enterprise | [Sur devis] | [€___] | [€___] | [€___] |")
            lines.append("")

        elif sec_key == "segmentation":
            lines.append("### Personas cibles")
            lines.append("")
            lines.append("#### Persona 1 — [Nom / Titre]")
            lines.append("- **Profil :** [Description]")
            lines.append("- **Taille du segment :** [___] entreprises / [___] utilisateurs")
            lines.append("- **Budget moyen :** [€___/an]")
            lines.append("- **Canaux :** [Canaux d'acquisition]")
            lines.append("- **Pain points :** [Douleurs principales]")
            lines.append("- **Decision maker :** [Qui achète]")
            lines.append("")
            lines.append("#### Persona 2 — [Nom / Titre]")
            lines.append("- **Profil :** [Description]")
            lines.append("- **Taille du segment :** [___]")
            lines.append("- **Budget moyen :** [€___/an]")
            lines.append("- **Canaux :** [Canaux d'acquisition]")
            lines.append("- **Pain points :** [Douleurs principales]")
            lines.append("- **Decision maker :** [Qui achète]")
            lines.append("")

        elif sec_key == "positioning":
            lines.append("### Positionnement recommandé")
            lines.append("")
            lines.append("**USP (Unique Selling Proposition) :**")
            lines.append("> [Notre produit] est [la seule solution / la première] qui [bénéfice unique]")
            lines.append("> pour [cible] qui [besoin spécifique], contrairement à [alternative principale]")
            lines.append("> qui [limitation de l'alternative].")
            lines.append("")
            lines.append("**Messaging par persona :**")
            lines.append("")
            lines.append("| Persona | Message principal | Proof point |")
            lines.append("|---------|------------------|-------------|")
            lines.append("| [Persona 1] | [Message] | [Preuve] |")
            lines.append("| [Persona 2] | [Message] | [Preuve] |")
            lines.append("")
            lines.append("**Différenciateurs clés :**")
            lines.append("")
            lines.append("1. **[Différenciateur 1]** — [Pourquoi c'est un avantage]")
            lines.append("2. **[Différenciateur 2]** — [Pourquoi c'est un avantage]")
            lines.append("3. **[Différenciateur 3]** — [Pourquoi c'est un avantage]")
            lines.append("")

        elif sec_key == "recommendations":
            lines.append("| # | Recommandation | Priorité | Département | Délai | Impact |")
            lines.append("|:-:|---------------|:--------:|:-----------:|:-----:|:------:|")
            lines.append("| 1 | [Action 1] | 🔴 CRITICAL | [Dept] | [___] | [___] |")
            lines.append("| 2 | [Action 2] | 🟠 HIGH | [Dept] | [___] | [___] |")
            lines.append("| 3 | [Action 3] | 🟡 MEDIUM | [Dept] | [___] | [___] |")
            lines.append("| 4 | [Action 4] | 🟡 MEDIUM | [Dept] | [___] | [___] |")
            lines.append("| 5 | [Action 5] | 🟢 LOW | [Dept] | [___] | [___] |")
            lines.append("")
            lines.append("**Quick wins (< 2 semaines) :**")
            lines.append("1. [Quick win 1]")
            lines.append("2. [Quick win 2]")
            lines.append("")
            lines.append("**Investissements stratégiques (3-6 mois) :**")
            lines.append("1. [Investissement 1]")
            lines.append("2. [Investissement 2]")
            lines.append("")

        elif sec_key == "appendices":
            lines.append("### Sources complètes")
            lines.append("")
            lines.append("| # | Source | URL | Date accès | Confiance |")
            lines.append("|:-:|--------|-----|:----------:|:---------:|")
            lines.append("| 1 | [Source] | [URL] | [Date] | HIGH/MEDIUM/LOW |")
            lines.append("")
            lines.append("### Glossaire")
            lines.append("")
            lines.append("| Terme | Définition |")
            lines.append("|-------|------------|")
            lines.append("| TAM | Total Addressable Market — marché total théorique |")
            lines.append("| SAM | Serviceable Addressable Market — marché accessible |")
            lines.append("| SOM | Serviceable Obtainable Market — marché capturable |")
            lines.append("| CAC | Customer Acquisition Cost — coût d'acquisition client |")
            lines.append("| LTV | Lifetime Value — valeur vie client |")
            lines.append("| ARPU | Average Revenue Per User — revenu moyen par utilisateur |")
            lines.append("| NPS | Net Promoter Score — indicateur de satisfaction client |")
            lines.append("| CAGR | Compound Annual Growth Rate — taux de croissance annuel composé |")
            lines.append("")

    # Footer
    lines.append(_ai_footer())

    report_content = "\n".join(lines)

    # Save to file if output_path specified or auto-generate
    saved_path: str | None = None
    if output_path:
        out = Path(output_path)
        if ".." in str(out):
            return {"ok": False, "error": "Path traversal not allowed"}
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report_content, encoding="utf-8")
        saved_path = str(out)
    else:
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower())[:60].strip("-")
        out_dir = _ensure_output_dir()
        date_str = datetime.now(UTC).strftime("%Y%m%d")
        out_file = out_dir / f"{date_str}-{slug}.md"
        out_file.write_text(report_content, encoding="utf-8")
        saved_path = str(out_file)

    result = {
        "ok": True,
        "title": title,
        "timestamp": ts,
        "sections_generated": used_sections,
        "sections_count": len(used_sections),
        "report_length_chars": len(report_content),
        "report_length_lines": len(lines),
        "output_path": saved_path,
        "language": language,
        "report_preview": report_content[:2000] + ("..." if len(report_content) > 2000 else ""),
        "cross_department_usage": {
            "CEO": "Executive Summary + Recommandations",
            "CFO": "Financial Analysis + Market Overview (TAM/SAM)",
            "CTO": "Competitive Landscape (tech stack) + Appendices",
            "Marketing": "Positioning + Segmentation + Competitive Landscape",
            "Commercial": "Competitive Landscape (battlecards) + Pricing",
            "Legal": "Market Overview (réglementation) + Appendices",
            "HR": "Appendices (benchmark salariaux si inclus)",
        },
        "ai_disclaimer": "⚠️ Rapport généré par IA — validation par un analyste senior requise.",
    }

    return result


# ── Tool: openclaw_market_research_monitor ───────────────────────────────────

def openclaw_market_research_monitor(
    action: str = "status",
    competitor: str | None = None,
    watch: list[str] | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """
    Continuous competitive monitoring — track competitor moves and market shifts.

    Actions:
      - add: Add a competitor to the watchlist
      - remove: Remove a competitor from the watchlist
      - update: Log a competitive event/move
      - status: Show current watchlist and recent events
      - export: Export monitoring data
    """
    ts = _timestamp()

    if action == "add":
        if not competitor:
            return {"ok": False, "error": "competitor name required for 'add' action"}
        watch_items = watch or ["pricing", "features", "funding", "headcount"]
        _MONITOR_WATCHLIST[competitor] = {
            "added_at": ts,
            "watch_items": watch_items,
            "events": [],
            "last_checked": ts,
        }
        return {
            "ok": True,
            "action": "add",
            "competitor": competitor,
            "watch_items": watch_items,
            "watchlist_size": len(_MONITOR_WATCHLIST),
            "message": f"'{competitor}' added to watchlist with {len(watch_items)} monitoring items.",
        }

    elif action == "remove":
        if not competitor:
            return {"ok": False, "error": "competitor name required for 'remove' action"}
        if competitor not in _MONITOR_WATCHLIST:
            return {"ok": False, "error": f"'{competitor}' not in watchlist"}
        del _MONITOR_WATCHLIST[competitor]
        return {
            "ok": True,
            "action": "remove",
            "competitor": competitor,
            "watchlist_size": len(_MONITOR_WATCHLIST),
            "message": f"'{competitor}' removed from watchlist.",
        }

    elif action == "update":
        if not competitor:
            return {"ok": False, "error": "competitor name required for 'update' action"}
        if competitor not in _MONITOR_WATCHLIST:
            return {"ok": False, "error": f"'{competitor}' not in watchlist. Use action='add' first."}
        event = {
            "timestamp": ts,
            "notes": notes or "[No notes provided]",
            "categories": watch or ["general"],
        }
        _MONITOR_WATCHLIST[competitor]["events"].append(event)
        _MONITOR_WATCHLIST[competitor]["last_checked"] = ts
        return {
            "ok": True,
            "action": "update",
            "competitor": competitor,
            "event": event,
            "total_events": len(_MONITOR_WATCHLIST[competitor]["events"]),
            "message": f"Event logged for '{competitor}'.",
        }

    elif action == "status":
        watchlist_summary: list[dict[str, Any]] = []
        for name, data in _MONITOR_WATCHLIST.items():
            watchlist_summary.append({
                "competitor": name,
                "watch_items": data["watch_items"],
                "events_count": len(data["events"]),
                "last_checked": data["last_checked"],
                "recent_events": data["events"][-3:] if data["events"] else [],
            })
        return {
            "ok": True,
            "action": "status",
            "watchlist_size": len(_MONITOR_WATCHLIST),
            "watchlist": watchlist_summary,
            "timestamp": ts,
        }

    elif action == "export":
        return {
            "ok": True,
            "action": "export",
            "timestamp": ts,
            "watchlist_size": len(_MONITOR_WATCHLIST),
            "data": {
                name: {
                    "watch_items": d["watch_items"],
                    "events_count": len(d["events"]),
                    "events": d["events"],
                    "added_at": d["added_at"],
                    "last_checked": d["last_checked"],
                }
                for name, d in _MONITOR_WATCHLIST.items()
            },
        }

    return {"ok": False, "error": f"Unknown action: {action}. Valid: add, remove, update, status, export"}


# ── TOOLS registry ───────────────────────────────────────────────────────────

_MARKET_RESEARCH_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean", "description": "Whether the operation succeeded"},
        "sector": {"type": "string", "description": "Market sector analyzed"},
        "timestamp": {"type": "string", "description": "ISO timestamp"},
    },
    "required": ["ok"],
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_market_competitive_analysis",
        "title": "Competitive Landscape Analysis",
        "description": (
            "Full competitive landscape analysis. Produces feature matrix, "
            "SWOT per competitor, and positioning map framework. "
            "Accessible to all departments."
        ),
        "category": "market_research",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "outputSchema": _MARKET_RESEARCH_OUTPUT_SCHEMA,
        "handler": openclaw_market_competitive_analysis,
        "inputSchema": {
            "type": "object",
            "properties": {
                "sector": {"type": "string", "description": "Target market sector (e.g. 'SaaS project management')"},
                "competitors": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of competitor names to analyze",
                },
                "geography": {"type": "string", "description": "Geographic scope (default: Global)"},
                "criteria": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Comparison criteria (default: standard 12 criteria)",
                },
                "include_swot": {"type": "boolean", "default": True, "description": "Include SWOT analysis per competitor"},
                "include_positioning": {"type": "boolean", "default": True, "description": "Include positioning map"},
                "our_product": {"type": "string", "description": "Our product name for comparison row"},
            },
            "required": ["sector"],
        },
    },
    {
        "name": "openclaw_market_sizing",
        "title": "Market Sizing (TAM/SAM/SOM)",
        "description": (
            "TAM/SAM/SOM market sizing with top-down and bottom-up approaches. "
            "Includes growth analysis, drivers, and inhibitors with confidence scoring."
        ),
        "category": "market_research",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "outputSchema": _MARKET_RESEARCH_OUTPUT_SCHEMA,
        "handler": openclaw_market_sizing,
        "inputSchema": {
            "type": "object",
            "properties": {
                "sector": {"type": "string", "description": "Target market sector"},
                "geography": {"type": "string", "description": "Geographic scope (default: Global)"},
                "target_segment": {"type": "string", "description": "Specific target segment"},
                "horizon_years": {"type": "integer", "default": 5, "description": "Forecast horizon in years"},
                "known_data": {"type": "object", "description": "Pre-existing data points (market size, CAGR, etc.)"},
                "approach": {
                    "type": "string",
                    "enum": ["top_down", "bottom_up", "both"],
                    "default": "both",
                    "description": "Sizing approach",
                },
            },
            "required": ["sector"],
        },
    },
    {
        "name": "openclaw_market_financial_benchmark",
        "title": "Financial Benchmarking",
        "description": (
            "Financial benchmarking — unit economics (CAC, LTV, ARPU, churn), "
            "pricing analysis, revenue comparisons. Cross-references with CFO data."
        ),
        "category": "market_research",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "outputSchema": _MARKET_RESEARCH_OUTPUT_SCHEMA,
        "handler": openclaw_market_financial_benchmark,
        "inputSchema": {
            "type": "object",
            "properties": {
                "sector": {"type": "string", "description": "Target market sector"},
                "metrics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Metrics to benchmark (CAC, LTV, churn, ARPU, etc.)",
                },
                "competitors": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Competitor names",
                },
                "our_data": {"type": "object", "description": "Our financial data for comparison"},
                "include_pricing": {"type": "boolean", "default": True, "description": "Include pricing analysis"},
            },
            "required": ["sector"],
        },
    },
    {
        "name": "openclaw_market_web_research",
        "title": "Web Research & OSINT",
        "description": (
            "Structured web research and OSINT intelligence gathering. "
            "Multi-source (Crunchbase, LinkedIn, G2, news...) with confidence scoring."
        ),
        "category": "market_research",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
        "outputSchema": _MARKET_RESEARCH_OUTPUT_SCHEMA,
        "handler": openclaw_market_web_research,
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Research query"},
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "OSINT sources to use (crunchbase, linkedin, g2, news, etc.)",
                },
                "competitor": {"type": "string", "description": "Specific competitor to research"},
                "max_results": {"type": "integer", "default": 10, "description": "Maximum results"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "openclaw_market_report_generate",
        "title": "Market Research Report Generator",
        "description": (
            "Generate a complete professional market research report in Markdown. "
            "Structured for cross-department readability: CEO (executive summary), "
            "CFO (financial), CTO (tech), Marketing (positioning), Commercial (battlecards)."
        ),
        "category": "market_research",
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"},
                "output_path": {"type": "string", "description": "Path to generated report"},
                "report_preview": {"type": "string", "description": "First 2000 chars of the report"},
            },
            "required": ["ok"],
        },
        "handler": openclaw_market_report_generate,
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Report title"},
                "sections": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Sections to include (default: all 9 sections)",
                },
                "data": {"type": "object", "description": "Pre-collected research data"},
                "output_path": {"type": "string", "description": "Output file path (auto-generated if omitted)"},
                "language": {
                    "type": "string",
                    "enum": ["fr", "en"],
                    "default": "fr",
                    "description": "Report language",
                },
                "include_toc": {"type": "boolean", "default": True, "description": "Include table of contents"},
            },
            "required": ["title"],
        },
    },
    {
        "name": "openclaw_market_research_monitor",
        "title": "Competitive Monitoring",
        "description": (
            "Continuous competitive monitoring. Actions: add/remove competitors, "
            "log market events, check watchlist status, export monitoring data."
        ),
        "category": "market_research",
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"},
                "action": {"type": "string"},
                "watchlist_size": {"type": "integer"},
            },
            "required": ["ok"],
        },
        "handler": openclaw_market_research_monitor,
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["add", "remove", "update", "status", "export"],
                    "default": "status",
                    "description": "Monitoring action",
                },
                "competitor": {"type": "string", "description": "Competitor name"},
                "watch": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Items to watch (pricing, features, funding, headcount, etc.)",
                },
                "notes": {"type": "string", "description": "Event notes (for 'update' action)"},
            },
            "required": [],
        },
    },
]
