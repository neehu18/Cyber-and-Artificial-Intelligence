# Handover Notes

## Artefact Name

Agentic AI Cyber Security Risk Assessment Tool

## Purpose

This artefact supports a security consultancy-style workflow. It allows a user to enter an AI or cyber security scenario and receive a structured assessment covering assets, threats, vulnerabilities, CIA impact, risk scoring and recommended controls.

## How to Run

1. Open the project folder.
2. Create and activate a Python virtual environment.
3. Install requirements:

```bash
pip install -r requirements.txt
```

4. Start the app:

```bash
streamlit run app.py
```

5. Use a sample scenario or enter a custom one.
6. Review each tab and export the report from the final tab.

## Main Files

| File | Purpose |
|---|---|
| `app.py` | Streamlit interface |
| `app_cli.py` | Command-line fallback runner |
| `risk_engine.py` | Main assessment logic |
| `knowledge_base.py` | Threat, vulnerability and control knowledge base |
| `crypto_tools.py` | Hashing, HMAC and AES-GCM demonstrations |
| `report_generator.py` | Markdown report creation |
| `sample_scenarios.json` | Fictional example scenarios |
| `project_management_documentation.md` | Project management evidence |

## What the Tool Does Well

- Provides structured security reasoning.
- Uses transparent rule-based logic that can be explained in a viva.
- Covers CIA, risk, firewall, IDS, vulnerability assessment and cryptography.
- Produces exportable reports and risk registers.
- Includes legal, ethical, privacy and AI transparency notes.

## Limitations

- It does not perform live scanning or connect to real networks.
- It does not automatically verify vulnerabilities.
- It uses rule-based scoring, so the output depends on the quality of scenario input.
- It should support, not replace, human security judgement.

## Recommended Demonstration Flow

1. Start with the sample scenario called **AI chatbot API data exposure**.
2. Show the generated executive summary.
3. Explain the CIA impact and risk register.
4. Open the controls tab and discuss firewall, IDS and vulnerability assessment controls.
5. Open the cryptography tab and demonstrate SHA-256/SHA3 and AES-GCM.
6. Open the legal/ethical/AI transparency tab.
7. Export the Markdown report and risk register.

## Future Improvements

- Add MITRE ATT&CK mapping.
- Add CVSS-style scoring.
- Add file upload for vulnerability scan outputs.
- Add authentication and role-based access for users.
- Add graph visualisation of assets, threats and controls.
