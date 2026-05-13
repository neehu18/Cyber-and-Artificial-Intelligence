"""Input/output utilities for scenarios and exported results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .models import ScenarioInput


def load_sample_scenarios(path: str | Path) -> List[Dict]:
    """Load sample scenarios from a JSON file."""
    file_path = Path(path)
    if not file_path.exists():
        return []
    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def scenario_from_dict(data: Dict) -> ScenarioInput:
    """Create a ScenarioInput object from a dictionary."""
    return ScenarioInput(
        title=data.get("title", "Untitled scenario"),
        organisation=data.get("organisation", "Example organisation"),
        scenario_description=data.get("scenario_description", ""),
        asset_category=data.get("asset_category", "Cloud application"),
        data_sensitivity=data.get("data_sensitivity", "Medium"),
        internet_exposure=data.get("internet_exposure", "Public internet"),
        authentication_strength=data.get("authentication_strength", "Moderate"),
        patching_status=data.get("patching_status", "Partially patched"),
        monitoring_level=data.get("monitoring_level", "Basic"),
        third_party_dependency=data.get("third_party_dependency", "Medium"),
        ai_usage_level=data.get("ai_usage_level", "Moderate"),
        business_criticality=data.get("business_criticality", "High"),
        regulatory_context=data.get("regulatory_context", "UK GDPR / Data Protection Act 2018"),
    )


def save_json_result(result_dict: Dict, path: str | Path) -> None:
    """Save a serialisable result dictionary to JSON."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", encoding="utf-8") as file:
        json.dump(result_dict, file, indent=2)
