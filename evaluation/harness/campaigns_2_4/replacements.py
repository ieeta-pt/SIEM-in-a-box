"""Validate amendments for invalid confirmatory executions.

The frozen campaign matrix is never edited. A replacement may differ from its
invalid source cell only by run ID, and the invalid artefacts stay in place.
"""

from __future__ import annotations

import json
from pathlib import Path

from run_revision import HERE, NEW_RESULTS, load_specs, sha256, validate_spec

PLAN = HERE / "replacement_plan.json"


def load_replacements(base_specs: list[dict] | None = None) -> dict[str, dict]:
    if not PLAN.exists():
        return {}
    base_specs = base_specs if base_specs is not None else load_specs("confirmatory")
    base = {spec["id"]: spec for spec in base_specs}
    plan = json.loads(PLAN.read_text())
    if plan.get("base_campaign_sha256") != sha256(HERE / "campaign_ready.json"):
        raise ValueError("Replacement plan is not tied to the frozen campaign")
    entries = plan.get("replacements")
    if not isinstance(entries, list):
        raise ValueError("Replacement plan must contain a list")
    out = {}
    replacement_ids = set()
    for entry in entries:
        original_id = entry["original_id"]
        spec = entry["replacement_spec"]
        replacement_id = spec["id"]
        if original_id not in base or original_id in out:
            raise ValueError(f"Unknown or duplicate original run: {original_id}")
        if replacement_id in base or replacement_id in replacement_ids:
            raise ValueError(f"Replacement ID collides with another cell: {replacement_id}")
        if spec != {**base[original_id], "id": replacement_id}:
            raise ValueError(f"Replacement changes experimental parameters: {original_id}")
        validate_spec(spec)
        original_dir = NEW_RESULTS / original_id
        assessment = original_dir / "execution_assessment.json"
        failure = original_dir / "failure.json"
        raw = original_dir / "raw.npz"
        if not all(path.is_file() for path in (assessment, failure, raw)):
            raise ValueError(f"Invalid original lacks preserved evidence: {original_id}")
        if sha256(assessment) != entry.get("invalid_assessment_sha256") or \
                sha256(failure) != entry.get("failure_sha256") or \
                sha256(raw) != entry.get("raw_sha256"):
            raise ValueError(f"Invalid original changed after replacement review: {original_id}")
        if json.loads(assessment.read_text()).get("execution_valid") is not False:
            raise ValueError(f"Original execution is not invalid: {original_id}")
        if not isinstance(entry.get("reason"), str) or len(entry["reason"].strip()) < 30:
            raise ValueError(f"Replacement reason is incomplete: {original_id}")
        out[original_id] = spec
        replacement_ids.add(replacement_id)
    return out
