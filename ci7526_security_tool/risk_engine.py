"""Transparent rule-based assessment engine for the coursework artefact.

The code is written as an explainable, Python-only agentic workflow. Each stage acts
like a simple specialist agent: asset agent, threat agent, risk agent and controls agent.
"""

from __future__ import annotations

from typing import Dict, List

from .knowledge_base import (
    AI_TRANSPARENCY_BASELINES,
    ASSET_MAP,
    CONTROL_LIBRARY,
    CRYPTOGRAPHY_BASELINES,
    DEFAULT_THREATS,
    FIREWALL_BASELINES,
    IDS_BASELINES,
    KEYWORD_THREATS,
    LEGAL_ETHICAL_PRIVACY_BASELINES,
    RATING_DESCRIPTIONS,
    VULNERABILITY_RULES,
    VULN_ASSESSMENT_BASELINES,
)
from .models import AssessmentResult, RiskFinding, ScenarioInput, make_timestamp


def unique_items(items: List[str]) -> List[str]:
    """Return items without duplicates while preserving the original order."""
    seen = set()
    output = []
    for item in items:
        key = item.strip().lower()
        if key and key not in seen:
            seen.add(key)
            output.append(item.strip())
    return output


def score_to_rating(score: int) -> str:
    """Convert a numeric risk score into a qualitative rating."""
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


def normalise_choice(value: str) -> str:
    """Normalise a string value while keeping it readable."""
    return (value or "Unknown").strip()


class AssetIdentificationAgent:
    """Identify important assets from the scenario."""

    def run(self, scenario: ScenarioInput) -> List[str]:
        assets = list(ASSET_MAP.get(scenario.asset_category, []))
        description = scenario.scenario_description.lower()

        if "api" in description:
            assets.append("API endpoints and access tokens")
        if "customer" in description or "personal" in description:
            assets.append("Customer personal data")
        if "payment" in description or "financial" in description:
            assets.append("Financial transaction records")
        if "model" in description or "ai" in description:
            assets.append("AI prompts, models and generated outputs")
        if "log" in description:
            assets.append("Security logs and audit trails")
        if scenario.business_criticality in ["High", "Critical"]:
            assets.append("Business continuity and service availability")

        if not assets:
            assets = ["Application data", "User accounts", "Service availability"]

        return unique_items(assets)


class ThreatIdentificationAgent:
    """Identify likely threats from keyword evidence and context choices."""

    def run(self, scenario: ScenarioInput) -> List[str]:
        text = f"{scenario.title} {scenario.scenario_description}".lower()
        threats = []

        for keyword, mapped_threats in KEYWORD_THREATS.items():
            if keyword in text:
                threats.extend(mapped_threats)

        if scenario.internet_exposure in ["Public internet", "Hybrid"]:
            threats.extend(["External attacker exploitation", "Automated scanning"])
        if scenario.third_party_dependency in ["Medium", "High"]:
            threats.extend(["Supplier compromise", "Third-party data leakage"])
        if scenario.ai_usage_level in ["Moderate", "High"]:
            threats.extend(["Prompt injection", "AI-assisted social engineering", "Sensitive prompt leakage"])

        threats.extend(DEFAULT_THREATS)
        return unique_items(threats)


class VulnerabilityIdentificationAgent:
    """Identify likely weaknesses from declared controls and scenario context."""

    def run(self, scenario: ScenarioInput) -> List[str]:
        vulnerabilities = []
        choices = [
            scenario.authentication_strength,
            scenario.patching_status,
            scenario.monitoring_level,
            scenario.third_party_dependency,
        ]

        for choice in choices:
            vulnerabilities.extend(VULNERABILITY_RULES.get(normalise_choice(choice), []))

        description = scenario.scenario_description.lower()
        if "misconfig" in description or "misconfiguration" in description:
            vulnerabilities.append("Security misconfiguration")
        if "exposed" in description or "public" in description:
            vulnerabilities.append("Excessive exposure of services or data")
        if "password" in description or "credential" in description:
            vulnerabilities.append("Credential management weakness")
        if "api" in description:
            vulnerabilities.append("Insufficient API validation, rate limiting or authorisation checks")
        if "third party" in description or "vendor" in description:
            vulnerabilities.append("Limited third-party assurance and monitoring")
        if "ai" in description or "prompt" in description:
            vulnerabilities.append("Insufficient AI prompt/data boundary controls")

        if not vulnerabilities:
            vulnerabilities.append("Insufficient evidence; further assessment required")

        return unique_items(vulnerabilities)


class CIAImpactAgent:
    """Assess confidentiality, integrity and availability impact in plain language."""

    def run(self, scenario: ScenarioInput, threats: List[str]) -> Dict[str, str]:
        confidentiality_terms = ["data", "leak", "exfiltration", "personal", "credential", "token", "prompt"]
        integrity_terms = ["modify", "tamper", "poison", "injection", "manipulation", "fraud"]
        availability_terms = ["ransomware", "denial", "disruption", "outage", "malware"]

        joined = " ".join(threats).lower() + " " + scenario.scenario_description.lower()

        confidentiality = "High" if any(term in joined for term in confidentiality_terms) else "Medium"
        integrity = "High" if any(term in joined for term in integrity_terms) else "Medium"
        availability = "High" if any(term in joined for term in availability_terms) else "Medium"

        if scenario.data_sensitivity in ["High", "Very high"]:
            confidentiality = "High"
        if scenario.business_criticality in ["High", "Critical"]:
            availability = "High"
        if scenario.business_criticality == "Low":
            availability = "Low"

        return {
            "Confidentiality": confidentiality,
            "Integrity": integrity,
            "Availability": availability,
        }


class RiskScoringAgent:
    """Create risk findings using transparent likelihood and impact scoring."""

    def _base_likelihood(self, scenario: ScenarioInput) -> int:
        likelihood = 2
        if scenario.internet_exposure == "Public internet":
            likelihood += 2
        elif scenario.internet_exposure == "Hybrid":
            likelihood += 1

        if scenario.authentication_strength in ["Weak", "Unknown"]:
            likelihood += 1
        if scenario.patching_status in ["Outdated", "Unknown"]:
            likelihood += 1
        if scenario.monitoring_level in ["None", "Basic"]:
            likelihood += 1
        if scenario.third_party_dependency == "High":
            likelihood += 1
        if scenario.ai_usage_level == "High":
            likelihood += 1
        return min(max(likelihood, 1), 5)

    def _base_impact(self, scenario: ScenarioInput) -> int:
        impact = 2
        if scenario.data_sensitivity == "Medium":
            impact += 1
        elif scenario.data_sensitivity == "High":
            impact += 2
        elif scenario.data_sensitivity == "Very high":
            impact += 3

        if scenario.business_criticality == "High":
            impact += 1
        elif scenario.business_criticality == "Critical":
            impact += 2
        return min(max(impact, 1), 5)

    def run(
        self,
        scenario: ScenarioInput,
        assets: List[str],
        threats: List[str],
        vulnerabilities: List[str],
        cia_impact: Dict[str, str],
    ) -> List[RiskFinding]:
        likelihood = self._base_likelihood(scenario)
        impact = self._base_impact(scenario)
        findings = []

        selected_threats = threats[: min(5, len(threats))]
        selected_vulnerabilities = vulnerabilities[: min(5, len(vulnerabilities))]
        selected_assets = assets[: min(5, len(assets))]
        cia_goals = list(cia_impact.keys())

        for index, threat in enumerate(selected_threats):
            asset = selected_assets[index % len(selected_assets)]
            vulnerability = selected_vulnerabilities[index % len(selected_vulnerabilities)]
            cia_goal = cia_goals[index % len(cia_goals)]

            adjusted_likelihood = likelihood
            adjusted_impact = impact
            if "ransomware" in threat.lower() or "denial" in threat.lower():
                adjusted_impact = min(5, adjusted_impact + 1)
            if "public" in vulnerability.lower() or "weak" in vulnerability.lower():
                adjusted_likelihood = min(5, adjusted_likelihood + 1)

            score = adjusted_likelihood * adjusted_impact
            rating = score_to_rating(score)
            controls = CONTROL_LIBRARY.get(cia_goal, [])[:3]
            findings.append(
                RiskFinding(
                    asset=asset,
                    threat=threat,
                    vulnerability=vulnerability,
                    cia_goal=cia_goal,
                    likelihood=adjusted_likelihood,
                    impact=adjusted_impact,
                    score=score,
                    rating=rating,
                    recommended_controls=controls,
                )
            )
        return findings


class ControlsRecommendationAgent:
    """Generate firewall, IDS and vulnerability assessment recommendations."""

    def run_firewall(self, scenario: ScenarioInput) -> List[str]:
        recommendations = list(FIREWALL_BASELINES)
        if scenario.internet_exposure == "Public internet":
            recommendations.append("Place public services behind a web application firewall where applicable")
        if "api" in scenario.scenario_description.lower():
            recommendations.append("Apply API gateway controls, token validation, request size limits and rate limiting")
        return unique_items(recommendations)

    def run_ids(self, scenario: ScenarioInput) -> List[str]:
        recommendations = list(IDS_BASELINES)
        if scenario.monitoring_level in ["None", "Basic"]:
            recommendations.append("Improve baseline logging before relying on advanced detection analytics")
        if scenario.ai_usage_level in ["Moderate", "High"]:
            recommendations.append("Monitor prompt abuse patterns, anomalous AI usage and unusual data export events")
        return unique_items(recommendations)

    def run_vulnerability_assessment(self, scenario: ScenarioInput) -> List[str]:
        recommendations = list(VULN_ASSESSMENT_BASELINES)
        if scenario.patching_status in ["Outdated", "Partially patched", "Unknown"]:
            recommendations.append("Create a remediation plan for unsupported software and missing security patches")
        if scenario.third_party_dependency in ["Medium", "High"]:
            recommendations.append("Request supplier assurance evidence, penetration test summaries or security questionnaires")
        return unique_items(recommendations)


class CryptoRecommendationAgent:
    """Recommend correct cryptography usage for the scenario."""

    def run(self, scenario: ScenarioInput) -> List[str]:
        recommendations = list(CRYPTOGRAPHY_BASELINES)
        if scenario.data_sensitivity in ["High", "Very high"]:
            recommendations.append("Use envelope encryption or managed KMS for highly sensitive datasets")
        if "api" in scenario.scenario_description.lower():
            recommendations.append("Sign API requests or use token binding where strong origin assurance is needed")
        if "log" in scenario.scenario_description.lower():
            recommendations.append("Protect audit log integrity using hash chains or append-only storage")
        if scenario.third_party_dependency in ["Medium", "High"]:
            recommendations.append("Define cryptographic requirements in third-party contracts and interface specifications")
        return unique_items(recommendations)


class LegalEthicalPrivacyAgent:
    """Generate legal, ethical and privacy considerations."""

    def run(self, scenario: ScenarioInput) -> List[str]:
        notes = list(LEGAL_ETHICAL_PRIVACY_BASELINES)
        if scenario.data_sensitivity in ["High", "Very high"]:
            notes.append("High sensitivity increases the need for explicit governance, auditability and data minimisation")
        if scenario.ai_usage_level in ["Moderate", "High"]:
            notes.append("AI-generated findings should be explainable, reviewed and not treated as automatically correct")
        if "health" in scenario.scenario_description.lower():
            notes.append("Health-related data requires stricter privacy safeguards and careful access governance")
        return unique_items(notes)


class AgenticSecurityAssessmentEngine:
    """Coordinate all specialist agents and produce one complete assessment."""

    def __init__(self) -> None:
        self.asset_agent = AssetIdentificationAgent()
        self.threat_agent = ThreatIdentificationAgent()
        self.vulnerability_agent = VulnerabilityIdentificationAgent()
        self.cia_agent = CIAImpactAgent()
        self.risk_agent = RiskScoringAgent()
        self.controls_agent = ControlsRecommendationAgent()
        self.crypto_agent = CryptoRecommendationAgent()
        self.legal_agent = LegalEthicalPrivacyAgent()

    def assess(self, scenario: ScenarioInput) -> AssessmentResult:
        assets = self.asset_agent.run(scenario)
        threats = self.threat_agent.run(scenario)
        vulnerabilities = self.vulnerability_agent.run(scenario)
        cia_impact = self.cia_agent.run(scenario, threats)
        findings = self.risk_agent.run(scenario, assets, threats, vulnerabilities, cia_impact)
        firewall = self.controls_agent.run_firewall(scenario)
        ids = self.controls_agent.run_ids(scenario)
        vuln_assessment = self.controls_agent.run_vulnerability_assessment(scenario)
        crypto = self.crypto_agent.run(scenario)
        legal = self.legal_agent.run(scenario)
        transparency = list(AI_TRANSPARENCY_BASELINES)
        executive_summary = self._make_executive_summary(scenario, findings)

        return AssessmentResult(
            scenario=scenario,
            generated_at=make_timestamp(),
            assets=assets,
            threats=threats,
            vulnerabilities=vulnerabilities,
            cia_impact=cia_impact,
            findings=findings,
            firewall_recommendations=firewall,
            ids_recommendations=ids,
            vulnerability_assessment_recommendations=vuln_assessment,
            cryptography_recommendations=crypto,
            legal_ethical_privacy_notes=legal,
            ai_transparency_notes=transparency,
            executive_summary=executive_summary,
        )

    def _make_executive_summary(self, scenario: ScenarioInput, findings: List[RiskFinding]) -> str:
        if not findings:
            return "No findings were generated. The scenario requires further manual review."

        highest = max(findings, key=lambda finding: finding.score)
        rating_description = RATING_DESCRIPTIONS.get(highest.rating, "Review required.")
        return (
            f"The assessment for {scenario.organisation} identified {len(findings)} main risk findings. "
            f"The highest-rated issue is '{highest.threat}' affecting '{highest.asset}', with a "
            f"{highest.rating} risk rating and a score of {highest.score}/25. {rating_description} "
            f"The recommended response is to apply layered controls covering access control, monitoring, "
            f"cryptography, vulnerability management and human review."
        )
