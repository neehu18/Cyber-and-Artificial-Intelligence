"""Tests for the transparent assessment engine."""

from ci7526_security_tool.io_utils import scenario_from_dict
from ci7526_security_tool.report_generator import generate_markdown_report
from ci7526_security_tool.risk_engine import AgenticSecurityAssessmentEngine


def test_engine_generates_complete_assessment():
    scenario = scenario_from_dict(
        {
            "title": "Test AI API data leakage",
            "organisation": "Test Organisation",
            "scenario_description": "A public AI chatbot connects to an API and may leak customer personal data through prompt injection.",
            "asset_category": "AI model or pipeline",
            "data_sensitivity": "High",
            "internet_exposure": "Public internet",
            "authentication_strength": "Moderate",
            "patching_status": "Partially patched",
            "monitoring_level": "Basic",
            "third_party_dependency": "High",
            "ai_usage_level": "High",
            "business_criticality": "High",
        }
    )

    engine = AgenticSecurityAssessmentEngine()
    result = engine.assess(scenario)
    report = generate_markdown_report(result)

    assert result.assets
    assert result.threats
    assert result.vulnerabilities
    assert result.findings
    assert result.firewall_recommendations
    assert result.ids_recommendations
    assert result.vulnerability_assessment_recommendations
    assert result.cryptography_recommendations
    assert "Risk Register" in report
    assert "AI Transparency" in report
