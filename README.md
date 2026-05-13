# CI7526 Agentic AI Cyber Security Risk Assessment Tool

## Project Overview

This repository contains a Python-only digital artefact for the CI7526 **Agentic AI for Cyber Security** coursework. The artefact is a Streamlit-based security risk assessment tool that supports a realistic handover scenario for a security consultancy.

The tool accepts a cyber security scenario and produces:

- asset identification
- threat and vulnerability analysis
- confidentiality, integrity and availability impact assessment
- qualitative risk scoring and risk register
- firewall recommendations
- IDS/IPS monitoring recommendations
- vulnerability assessment recommendations
- cryptography and data protection recommendations
- legal, ethical and privacy notes
- AI transparency notes
- downloadable Markdown, CSV and JSON outputs

The implementation uses transparent rule-based logic so that its decisions can be explained during a viva or handover meeting.

## Why This Artefact Fits the Coursework

The artefact is security-related and uses an AI-inspired agentic workflow. It separates the assessment into specialist stages: asset identification, threat identification, vulnerability identification, CIA impact assessment, risk scoring and control recommendation.

The tool supports the module topics of cyber security, artificial intelligence applications, cryptography, firewalls, intrusion detection systems, vulnerability assessment, ethics and privacy.

## Folder Structure

```text
ci7526_agentic_ai_cyber_tool/
âââ app.py
âââ app_cli.py
âââ requirements.txt
âââ README.md
âââ data/
â   âââ sample_scenarios.json
âââ ci7526_security_tool/
â   âââ __init__.py
â   âââ crypto_tools.py
â   âââ io_utils.py
â   âââ knowledge_base.py
â   âââ models.py
â   âââ report_generator.py
â   âââ risk_engine.py
âââ docs/
â   âââ acknowledgement_of_gai_contribution.md
â   âââ handover_notes.md
â   âââ project_management_documentation.md
â   âââ testing_checklist.md
âââ tests/
    âââ test_risk_engine.py
```

## Installation

Use Python 3.10 or above.

```bash
python -m venv .venv
```

Activate the environment.

Windows:

```bash
.venv\Scripts\activate
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies.

```bash
pip install -r requirements.txt
```

## Running the Streamlit App

```bash
streamlit run app.py
```

The app opens in the browser. Use a sample scenario or enter a custom scenario in the sidebar.

## Running the Command-Line Version

```bash
python app_cli.py
```

This generates a Markdown report in the `outputs/` folder.

## Running Tests

```bash
pytest
```

The test checks that the assessment engine generates risk findings, security controls and a report-ready output.

## Suggested Screenshots for Submission

Capture screenshots of:

1. the Streamlit home/risk assessment page
2. the risk register output
3. the firewall, IDS and vulnerability assessment recommendations
4. the cryptography demo page showing SHA and AES-GCM output
5. the legal/ethical/AI transparency page
6. the exported report preview
7. the GitHub repository page showing commits and files

## How to Use Sample Scenarios

The file `data/sample_scenarios.json` contains demonstration scenarios only. They are included so the artefact can be tested quickly during development and viva demonstration. Users can also type their own scenario in the app sidebar.

Sample scenarios are not a replacement for your explanation. In your final submission, you should select one realistic scenario, run the tool, take screenshots, export the report and explain the findings in your own words.
