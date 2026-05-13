"""Markdown report generator for the cyber security assessment artefact."""

from __future__ import annotations

from typing import Iterable

from .models import AssessmentResult, RiskFinding


def bullet_list(items: Iterable[str]) -> str:
    """Convert items into a markdown bullet list."""
    items = list(items)
    if not items:
        return "- No items generated."
    return "\n".join(f"- {item}" for item in items)


def findings_table(findings: list[RiskFinding]) -> str:
    """Create a markdown table for risk findings."""
    if not findings:
        return "No risk findings generated."

    rows = [
        "| Asset | Threat | Vulnerability | CIA Goal | Likelihood | Impact | Score | Rating |",
        "|---|---|---|---|---:|---:|---:|---|",
    ]
    for finding in findings:
        rows.append(
            "| {asset} | {threat} | {vulnerability} | {cia} | {likelihood} | {impact} | {score} | {rating} |".format(
                asset=finding.asset,
                threat=finding.threat,
                vulnerability=finding.vulnerability,
                cia=finding.cia_goal,
                likelihood=finding.likelihood,
                impact=finding.impact,
                score=finding.score,
                rating=finding.rating,
            )
        )
    return "\n".join(rows)


def controls_table(findings: list[RiskFinding]) -> str:
    """Create a markdown table listing controls for each risk finding."""
    if not findings:
        return "No controls generated."

    rows = [
        "| Risk | Recommended Controls |",
        "|---|---|",
    ]
    for finding in findings:
        controls = "<br>".join(finding.recommended_controls)
        rows.append(f"| {finding.threat} | {controls} |")
    return "\n".join(rows)


def generate_markdown_report(result: AssessmentResult) -> str:
    """Generate a complete markdown report from an assessment result."""
    scenario = result.scenario
    cia_lines = [f"- **{goal}:** {level}" for goal, level in result.cia_impact.items()]

    report = f"""# Agentic AI Cyber Security Risk Assessment Report

## 1. Assessment Metadata

- **Assessment title:** {scenario.title}
- **Organisation:** {scenario.organisation}
- **Generated at:** {result.generated_at}
- **Asset category:** {scenario.asset_category}
- **Regulatory context:** {scenario.regulatory_context}

## 2. Scenario Description

{scenario.scenario_description}

## 3. Executive Summary

{result.executive_summary}

## 4. Identified Assets

{bullet_list(result.assets)}

## 5. Threats and Vulnerabilities

### 5.1 Likely Threats

{bullet_list(result.threats)}

### 5.2 Likely Vulnerabilities

{bullet_list(result.vulnerabilities)}

## 6. CIA Security Goal Impact

{chr(10).join(cia_lines)}

## 7. Risk Register

{findings_table(result.findings)}

## 8. Recommended Risk Controls

{controls_table(result.findings)}

## 9. Firewall Recommendations

{bullet_list(result.firewall_recommendations)}

## 10. IDS/IPS Monitoring Recommendations

{bullet_list(result.ids_recommendations)}

## 11. Vulnerability Assessment Recommendations

{bullet_list(result.vulnerability_assessment_recommendations)}

## 12. Cryptography and Data Protection Recommendations

{bullet_list(result.cryptography_recommendations)}

## 13. Legal, Ethical and Privacy Considerations

{bullet_list(result.legal_ethical_privacy_notes)}

## 14. AI Transparency Notes

{bullet_list(result.ai_transparency_notes)}

## 15. Handover Notes

This artefact provides decision-support output for a line manager or security analyst. The recommendations should be reviewed before operational implementation. The most important next steps are to validate the scenario assumptions, confirm asset ownership, test the proposed controls, and document any residual risk that cannot be immediately remediated.

## 16. Acknowledgement of GAI Contribution

Generative AI was used to support ideation, structure, code drafting and refinement of this artefact. The final artefact should be reviewed, understood and adapted by the student before submission. Core reasoning, final judgement, screenshots, GitHub activity and viva explanation remain the student's responsibility.
"""
    return report
