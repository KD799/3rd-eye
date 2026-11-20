"""Load and validate offline Hugging Face/calibration profiles."""
import json
from pathlib import Path


def load_profiles(path=None):
    if path is None:
        path = Path(__file__).with_name("learned_profiles.json")
    path = Path(path)
    if not path.exists():
        return {"model": None, "sources": {}}
    with path.open("r", encoding="utf-8") as file:
        profile = json.load(file)
    if profile.get("model") != "explainable-median-mad-calibration":
        raise ValueError("Unsupported learned profile format")
    return profile


def get_profile(metric, profile=None):
    profile = profile or load_profiles()
    matches = []
    for source_name, source in profile["sources"].items():
        normal = source.get("normal", {}).get(metric)
        attack = source.get("attack", {}).get(metric)
        if normal or attack:
            matches.append({
                "source": source_name,
                "normal": normal,
                "attack": attack,
            })
    return matches
