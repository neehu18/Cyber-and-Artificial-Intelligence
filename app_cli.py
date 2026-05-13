"""Command-line version of the CI7526 security assessment tool.

This file allows the artefact to run as normal Python even when Streamlit is not used.
Run:
    python app_cli.py
"""

from pathlib import Path

from ci7526_security_tool.io_utils import load_sample_scenarios, scenario_from_dict
from ci7526_security_tool.report_generator import generate_markdown_report
from ci7526_security_tool.risk_engine import AgenticSecurityAssessmentEngine

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_PATH = BASE_DIR / "data" / "sample_scenarios.json"
OUTPUT_PATH = BASE_DIR / "outputs" / "cli_generated_report.md"


def main() -> None:
    samples = load_sample_scenarios(SAMPLE_PATH)
    if samples:
        scenario = scenario_from_dict(samples[0])
    else:
        raise FileNotFoundError("No sample scenarios found in data/sample_scenarios.json")

    engine = AgenticSecurityAssessmentEngine()
    result = engine.assess(scenario)
    report = generate_markdown_report(result)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(report, encoding="utf-8")

    print("CI7526 Agentic AI Cyber Security Assessment")
    print("=" * 52)
    print(result.executive_summary)
    print(f"\nReport saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
