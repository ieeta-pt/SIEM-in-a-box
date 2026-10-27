"""Exact generator-attempt records for the revision campaign.

The binary file is an uncompressed sequence of packed 25-byte little-endian
records: (seq:int64, wall_ns:int64, monotonic_ns:int64, sent_ok:uint8).
Writes are buffered by generator tick; no per-event fsync is performed.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

DTYPE = np.dtype([("seq", "<i8"), ("wall_ns", "<i8"),
                  ("monotonic_ns", "<i8"), ("sent_ok", "u1")], align=False)
assert DTYPE.itemsize == 25


def read(path: str | Path, manifest: dict) -> np.ndarray:
    path = Path(path)
    if path.stat().st_size != manifest["n_attempted"] * DTYPE.itemsize:
        raise ValueError("Event-log size differs from manifest attempt count")
    rows = (np.memmap(path, dtype=DTYPE, mode="r") if manifest["n_attempted"]
            else np.empty(0, dtype=DTYPE))
    if len(rows) != manifest["n_attempted"]:
        raise ValueError("Event-log record count mismatch")
    if len(rows):
        expected = np.arange(manifest["seq_start"], manifest["seq_end"], dtype=np.int64)
        if not np.array_equal(rows["seq"], expected):
            raise ValueError("Event-log IDs are not the full attempt sequence")
        if np.any(np.diff(rows["monotonic_ns"]) < 0):
            raise ValueError("Event-log monotonic clock moved backwards")
    if int(rows["sent_ok"].sum()) != manifest["n_sent"]:
        raise ValueError("Event-log sent count differs from manifest")
    if int((rows["sent_ok"] == 0).sum()) != manifest["send_errors"]:
        raise ValueError("Event-log send-error count differs from manifest")
    if np.any(rows["sent_ok"] > 1):
        raise ValueError("Invalid sent_ok value")
    return rows
