# Measurement harness

The code that ran the 269 runs and produced every table and figure of the paper. The results themselves are in [`../runs/`](../runs/) and [`../tables/`](../tables/).

## Files

| File | Role |
|---|---|
| `docker-compose.yml`, `configs/`, `wazuh/` | Systems under test: Elasticsearch, Kafka, Logstash and Kibana for the Elastic variants, and a single-node Wazuh for variant C (`wazuh/compose-bench.yml`). The Wazuh TLS certificates are generated locally with `wazuh/generate-indexer-certs.yml`. |
| `gen.py` | Load generator. Sends constant-rate nginx and sshd events, each carrying `bseq=<sequence>:<production time in ns>`. |
| `es_setup.py` | Index template and the ingest pipeline that stamps the time at which the indexer receives each event. |
| `run.py` | Campaign-1 run orchestrator: starts the stack, collectors and generators, injects outages, broker kills and floods, and reads every event back. |
| `analyze.py` | Per-run analysis: first receipt per ID, duplicates, loss, latency quantiles and recovery. |
| `campaign.json`, `phases.py`, `session.sh`, `stop.sh`, `hostlog.sh` | Campaign-1 run definitions, phase driver, stop request and host-condition log. |
| `session.py` | Driver of campaigns 2 to 4 (`./session.py list`, `./session.py N`). |
| `campaigns_2_4/` | Campaigns 2 to 4: frozen protocol (`PRE-RUN-PROTOCOL.md`), metric definitions (`decisions.md`), run matrices and their locks, the executor (`run_revision.py`, `campaign_session.py`, `telemetry.py`, `host_affinity.py`, `eventlog.py`), the validity checks (`assess_run.py`), the variant pipelines (`config_revision.py`) and the alert cells (`alerts_e2e/`). |
| `aggregate.py`, `flood_report.py`, `paper_numbers.py` | Campaign-1 tables and every campaign-1 number quoted in the paper. |
| `campaigns_2_4/reanalyse.py` | Re-analysis of campaign 1 with the first-receipt definitions of `decisions.md`. |
| `campaigns_2_4/derived/*.py` | Tables of campaigns 2 to 4. `wazuh_alert_latency.py` reads the Wazuh alert index and needs the Wazuh indexer running. |
| `figs.py` | The four result figures, written to `../figures/`. |
| `NOTES.md` | Campaign 1: testbed, methodological decisions and anomalies found while building the harness. |

The directory `campaigns_2_4/` was called `revision_20261019/` when the runs were executed, which is the name recorded in the `config_manifest.json` of every run.

## Reproducing the tables and figures

The analysis needs the raw per-event records (`raw.npz` with every indexed event and `gen-<stream>.events.bin` with every send attempt), which are distributed as a separate archive because of their size (3.2 GB). Extract it in this directory, which recreates `results/` (campaign 1) and `campaigns_2_4/new_results/` (campaigns 2 to 4, with the pilots, session logs and aborted attempts). No container is needed for the analysis.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

.venv/bin/python aggregate.py                  # campaign-1 phase tables -> results/summary.json
.venv/bin/python flood_report.py               # campaign-1 flood windows -> results/flood_summary.json
.venv/bin/python paper_numbers.py              # campaign-1 numbers -> results/paper_numbers.txt
.venv/bin/python campaigns_2_4/reanalyse.py
.venv/bin/python campaigns_2_4/derived/paper_evidence.py
.venv/bin/python campaigns_2_4/derived/paper_evidence_e3.py
.venv/bin/python campaigns_2_4/derived/paper_evidence_e5.py
.venv/bin/python campaigns_2_4/derived/backlog_sensitivity.py
.venv/bin/python figs.py                       # -> ../figures/
```

The outputs are the files collected in [`../tables/`](../tables/), whose README maps each one to its source script.

## Running new measurements

The harness expects the host of the paper: Linux with Docker, the SUT pinned to CPUs 0 to 7 and the generators and collectors to CPUs 12 to 19, mains power, Turbo Boost off and no other containers. `session.sh` (campaign 1) and `session.py` (campaigns 2 to 4) refuse to start otherwise, and `session.py` also checks temperature, free disk and the affinity of every user thread before each run.

```bash
./session.sh list        # campaign-1 phases and progress
./session.sh 3           # run phase 3, resumable
./stop.sh                # stop after the current run

./session.py list        # campaign 2 to 4 rows 1 to 76 with validity and time estimates
./session.py 52 53       # run the listed rows in order; valid rows are never re-run
```

`run_revision.py` refuses any run whose specification is not covered by its lock, so a new cell requires a new matrix entry and a regenerated lock.
