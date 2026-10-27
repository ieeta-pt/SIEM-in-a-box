"""Run one protocol-identical replacement for a preserved invalid cell."""

from __future__ import annotations

import argparse
import fcntl
import json

from replacements import load_replacements
from run_revision import NEW_RESULTS, execute_one, require_protocol_lock


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True, help="replacement run ID")
    args = parser.parse_args()
    require_protocol_lock()
    plans = load_replacements()
    matches = [spec for spec in plans.values() if spec["id"] == args.id]
    if len(matches) != 1:
        raise ValueError(f"Unreviewed replacement ID: {args.id}")
    spec = matches[0]
    with (NEW_RESULTS / ".campaign.lock").open("w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(f"starting replacement {spec['id']}", flush=True)
        result = execute_one(spec)
        print(json.dumps({"finished": spec["id"], "status": result["status"]}), flush=True)


if __name__ == "__main__":
    main()
