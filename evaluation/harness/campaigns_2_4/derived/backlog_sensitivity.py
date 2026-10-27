"""Exploratory threshold sensitivity; never changes the fixed primary endpoint."""
import csv
import json
from pathlib import Path
import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent / 'new_results'
rows = []
with (HERE / 'paper_recovery.csv').open() as handle:
    runs = list(csv.DictReader(handle))
for item in runs:
    folder = ROOT / item['run_id']
    result = json.loads((folder / 'result.json').read_text())
    manifest = json.loads((folder / 'gen-nginx.json').read_text())
    data = np.genfromtxt(folder / 'backlog-nginx.csv', delimiter=',', names=True)
    grid = data['time_ns'].astype(np.int64)
    backlog = data['backlog_to_request_receipt'].astype(np.int64)
    ready = result['fault']['ready_ns']
    start = result['fault']['effective_start_ns']
    baseline = float(np.median(backlog[(grid >= start-40*10**9) & (grid < start-10*10**9)]))
    select = (grid >= ready) & (grid <= manifest['end_ns'])
    for extra in (25, 50, 75, 100, 200, 400):
        below = (backlog[select] <= baseline + extra).astype(int)
        candidates = np.flatnonzero(np.convolve(below, np.ones(31, dtype=int), mode='valid') == 31)
        seconds = ((int(grid[select][candidates[0]]) - ready)/1e9 if len(candidates) else None)
        rows.append(dict(run_id=item['run_id'],variant=item['variant'],rate=item['rate'],
                         pause_s=item['pause_s'],repetition=item['repetition'],
                         baseline=baseline,additional_events=extra,
                         status='observed' if seconds is not None else 'unobserved_during_generation',
                         seconds_after_ready=seconds))
with (HERE / 'backlog_threshold_sensitivity.csv').open('w', newline='') as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
print('Wrote exploratory 21-run x 6-threshold sensitivity; primary endpoint unchanged.')
