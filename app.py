"""Streamlit front-end for the CI7526 Agentic AI Cyber Security Tool.

Run with:
    streamlit run app.py
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from ci7526_security_tool.crypto_tools import (
    aes_gcm_decrypt_demo,
    aes_gcm_encrypt_demo,
    demonstrate_hash_avalanche,
    generate_demo_key,
    hmac_sha256,
)
from ci7526_security_tool.io_utils import load_sample_scenarios
from ci7526_security_tool.models import ScenarioInput
from ci7526_security_tool.risk_engine import AgenticSecurityAssessmentEngine

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_PATH = BASE_DIR / "data" / "sample_scenarios.json"


st.set_page_config(
    page_title="CI7526 Agentic AI Cyber Security Tool",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_data
def cached_samples() -> list[dict]:
    """Load sample scenarios once for the Streamlit session."""
    return load_sample_scenarios(SAMPLE_PATH)


def make_dataframe_from_findings(findings) -> pd.DataFrame:
    """Convert risk findings to a dataframe for display and export."""
    return pd.DataFrame(
        [
            {
                "Asset": finding.asset,
                "Threat": finding.threat,
                "Vulnerability": finding.vulnerability,
                "CIA Goal": finding.cia_goal,
                "Likelihood": finding.likelihood,
                "Impact": finding.impact,
                "Score": finding.score,
                "Rating": finding.rating,
                "Controls": "; ".join(finding.recommended_controls),
            }
            for finding in findings
        ]
    )


def rating_badge(rating: str) -> str:
    """Return a plain text marker for a risk rating."""
    badges = {
        "Low": "🟢 Low",
        "Medium": "🟡 Medium",
        "High": "🟠 High",
        "Critical": "🔴 Critical",
    }
    return badges.get(rating, rating)


st.title("🛡️ Agentic AI Cyber Security Risk Assessment Tool")
st.caption("Python-only coursework artefact for CI7526: Cyber and Artificial Intelligence Applications")

with st.sidebar:
    st.header("Assessment Inputs")
    samples = cached_samples()
    sample_titles = [sample["title"] for sample in samples]
    input_mode = st.radio("Input mode", ["Use sample scenario", "Create custom scenario"])

    selected_sample = None
    if input_mode == "Use sample scenario" and samples:
        selected_title = st.selectbox("Choose sample scenario", sample_titles)
        selected_sample = next(sample for sample in samples if sample["title"] == selected_title)
    elif input_mode == "Use sample scenario" and not samples:
        st.warning("No sample scenarios found. Create a custom scenario instead.")

    default_data = selected_sample or {
        "title": "AI-enabled customer support data exposure",
        "organisation": "Example Security Consultancy Client",
        "scenario_description": (
            "A public AI customer support chatbot connects to an API that can access customer records. "
            "The organisation is concerned about prompt injection, data leakage, weak monitoring and third-party risk."
        ),
        "asset_category": "AI model or pipeline",
        "data_sensitivity": "High",
        "internet_exposure": "Public internet",
        "authentication_strength": "Moderate",
        "patching_status": "Partially patched",
        "monitoring_level": "Basic",
        "third_party_dependency": "High",
        "ai_usage_level": "High",
        "business_criticality": "High",
        "regulatory_context": "UK GDPR / Data Protection Act 2018",
    }

    title = st.text_input("Assessment title", value=default_data["title"])
    organisation = st.text_input("Organisation", value=default_data["organisation"])
    scenario_description = st.text_area(
        "Scenario description",
        value=default_data["scenario_description"],
        height=180,
    )

    asset_category = st.selectbox(
        "Primary asset category",
        [
            "Personal data",
            "Financial data",
            "AI model or pipeline",
            "Network infrastructure",
            "Cloud application",
            "Operational system",
        ],
        index=[
            "Personal data",
            "Financial data",
            "AI model or pipeline",
            "Network infrastructure",
            "Cloud application",
            "Operational system",
        ].index(default_data["asset_category"]),
    )

    data_sensitivity = st.selectbox(
        "Data sensitivity",
        ["Low", "Medium", "High", "Very high"],
        index=["Low", "Medium", "High", "Very high"].index(default_data["data_sensitivity"]),
    )
    internet_exposure = st.selectbox(
        "Internet exposure",
        ["Internal only", "Hybrid", "Public internet"],
        index=["Internal only", "Hybrid", "Public internet"].index(default_data["internet_exposure"]),
    )
    authentication_strength = st.selectbox(
        "Authentication strength",
        ["Weak", "Moderate", "Strong", "Unknown"],
        index=["Weak", "Moderate", "Strong", "Unknown"].index(default_data["authentication_strength"]),
    )
    patching_status = st.selectbox(
        "Patching status",
        ["Outdated", "Partially patched", "Current", "Unknown"],
        index=["Outdated", "Partially patched", "Current", "Unknown"].index(default_data["patching_status"]),
    )
    monitoring_level = st.selectbox(
        "Monitoring level",
        ["None", "Basic", "Advanced"],
        index=["None", "Basic", "Advanced"].index(default_data["monitoring_level"]),
    )
    third_party_dependency = st.selectbox(
        "Third-party dependency",
        ["Low", "Medium", "High"],
        index=["Low", "Medium", "High"].index(default_data["third_party_dependency"]),
    )
    ai_usage_level = st.selectbox(
        "AI usage level",
        ["None", "Low", "Moderate", "High"],
        index=["None", "Low", "Moderate", "High"].index(default_data["ai_usage_level"]),
    )
    business_criticality = st.selectbox(
        "Business criticality",
        ["Low", "Medium", "High", "Critical"],
        index=["Low", "Medium", "High", "Critical"].index(default_data["business_criticality"]),
    )
    regulatory_context = st.text_input("Regulatory context", value=default_data["regulatory_context"])

scenario = ScenarioInput(
    title=title,
    organisation=organisation,
    scenario_description=scenario_description,
    asset_category=asset_category,
    data_sensitivity=data_sensitivity,
    internet_exposure=internet_exposure,
    authentication_strength=authentication_strength,
    patching_status=patching_status,
    monitoring_level=monitoring_level,
    third_party_dependency=third_party_dependency,
    ai_usage_level=ai_usage_level,
    business_criticality=business_criticality,
    regulatory_context=regulatory_context,
)

engine = AgenticSecurityAssessmentEngine()
result = engine.assess(scenario)
findings_df = make_dataframe_from_findings(result.findings)

highest_finding = max(result.findings, key=lambda item: item.score) if result.findings else None

summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
with summary_col1:
    st.metric("Risk Findings", len(result.findings))
with summary_col2:
    st.metric("Highest Score", highest_finding.score if highest_finding else 0)
with summary_col3:
    st.metric("Highest Rating", rating_badge(highest_finding.rating) if highest_finding else "N/A")
with summary_col4:
    st.metric("CIA Goals Covered", len(result.cia_impact))

st.info(result.executive_summary)

tab1, tab2, tab3, tab4, tab5 = st.tabs(
    [
        "1. Risk Assessment",
        "2. Controls",
        "3. Cryptography Demo",
        "4. Legal/Ethical/AI Transparency",
        "5. Export Data",
    ]
)

with tab1:
    st.subheader("Agent Workflow Output")
    st.write(
        "The tool applies a transparent agentic workflow: asset identification, threat identification, "
        "vulnerability identification, CIA impact assessment, risk scoring and control recommendation."
    )

    left, right = st.columns(2)
    with left:
        st.markdown("### Identified Assets")
        for asset in result.assets:
            st.write(f"- {asset}")

        st.markdown("### CIA Impact")
        cia_df = pd.DataFrame(
            [{"Security goal": goal, "Impact level": level} for goal, level in result.cia_impact.items()]
        )
        st.dataframe(cia_df, use_container_width=True, hide_index=True)

    with right:
        st.markdown("### Likely Threats")
        for threat in result.threats[:10]:
            st.write(f"- {threat}")

        st.markdown("### Likely Vulnerabilities")
        for vulnerability in result.vulnerabilities[:10]:
            st.write(f"- {vulnerability}")

    st.markdown("### Risk Register")
    st.dataframe(findings_df, use_container_width=True, hide_index=True)

    st.markdown("### Risk Score Chart")
    if not findings_df.empty:
        chart_df = findings_df[["Threat", "Score"]].set_index("Threat")
        st.bar_chart(chart_df)

with tab2:
    st.subheader("Network Security and Vulnerability Controls")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("### Firewall Recommendations")
        for item in result.firewall_recommendations:
            st.write(f"- {item}")
    with col2:
        st.markdown("### IDS/IPS Recommendations")
        for item in result.ids_recommendations:
            st.write(f"- {item}")
    with col3:
        st.markdown("### Vulnerability Assessment")
        for item in result.vulnerability_assessment_recommendations:
            st.write(f"- {item}")

    st.markdown("### Finding-Level Controls")
    for finding in result.findings:
        with st.expander(f"{finding.rating} risk: {finding.threat}"):
            st.write(f"**Asset:** {finding.asset}")
            st.write(f"**Vulnerability:** {finding.vulnerability}")
            st.write(f"**CIA goal:** {finding.cia_goal}")
            for control in finding.recommended_controls:
                st.write(f"- {control}")

with tab3:
    st.subheader("Cryptography Recommendation and Demonstration")
    st.markdown("### Scenario-Based Cryptography Recommendations")
    for recommendation in result.cryptography_recommendations:
        st.write(f"- {recommendation}")

    st.markdown("### Hash Function Integrity Demo")
    hash_col1, hash_col2 = st.columns(2)
    with hash_col1:
        original_message = st.text_input("Original message", value="SECURITY MESSAGE")
    with hash_col2:
        changed_message = st.text_input("Changed message", value="SECURITY MESSAGE!")

    hash_output = demonstrate_hash_avalanche(original_message, changed_message)
    hash_df = pd.DataFrame(
        [
            {"Algorithm": "SHA-256", "Original digest": hash_output["sha256_original"], "Changed digest": hash_output["sha256_changed"]},
            {"Algorithm": "SHA3-256", "Original digest": hash_output["sha3_256_original"], "Changed digest": hash_output["sha3_256_changed"]},
        ]
    )
    st.dataframe(hash_df, use_container_width=True, hide_index=True)
    st.caption(hash_output["interpretation"])

    st.markdown("### HMAC Origin Integrity Demo")
    hmac_key = st.text_input("HMAC demonstration key", value="demo-secret-key", type="password")
    st.code(hmac_sha256(original_message, hmac_key), language="text")

    st.markdown("### AES-GCM Encryption Demo")
    aes_message = st.text_area("Plaintext for AES-GCM demo", value="This is a confidential demonstration message.")
    aes_key = st.text_input("AES demonstration key", value="coursework-demo-key", type="password")

    if st.button("Run AES-GCM Encryption Demo"):
        aes_output = aes_gcm_encrypt_demo(aes_message, aes_key)
        st.session_state["aes_output"] = aes_output

    aes_output = st.session_state.get("aes_output")
    if aes_output:
        if aes_output.get("available") == "Yes":
            st.success("AES-GCM encryption completed.")
            st.json(aes_output)
            decrypt_output = aes_gcm_decrypt_demo(
                aes_output["ciphertext_base64"],
                aes_output["nonce_base64"],
                aes_key,
            )
            st.write("Decryption check:")
            st.json(decrypt_output)
        else:
            st.warning(aes_output.get("error"))

with tab4:
    st.subheader("Legal, Ethical, Privacy and AI Transparency")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Legal, Ethical and Privacy Notes")
        for note in result.legal_ethical_privacy_notes:
            st.write(f"- {note}")
    with col2:
        st.markdown("### AI Transparency Notes")
        for note in result.ai_transparency_notes:
            st.write(f"- {note}")

    st.markdown("### Suggested Acknowledgement of GAI Contribution")
    st.info(
        "Generative AI was used to support ideation, structure, code drafting and refinement. "
        "The final artefact, testing, interpretation, screenshots, GitHub repository and viva explanation "
        "must be reviewed and owned by the student."
    )

with tab5:
    st.subheader("Export Assessment Data")
    st.download_button(
        "Download Risk Register CSV",
        data=findings_df.to_csv(index=False),
        file_name="risk_register.csv",
        mime="text/csv",
    )
    st.download_button(
        "Download Full Result JSON",
        data=json.dumps(result.to_dict(), indent=2),
        file_name="assessment_result.json",
        mime="application/json",
    )
