# Derived tables

Every number in the paper comes from one of these files. They are produced by the scripts in [`../harness/`](../harness/) from the raw per-event records, and each row names the run it comes from, whose full result is in [`../runs/`](../runs/). The prefix gives the campaign (`c1` to `c4`).

## From the paper to the files

| In the paper | Files |
|---|---|
| Table 3, campaigns | [`../runs/index.csv`](../runs/index.csv) |
| RQ1, campaign-1 outages, file sources and Kafka kill | `c1_paper_numbers.txt`, `c1_outage_recovery.csv`, `c1_loss_windows.csv` |
| Figure 2, campaign-2 outages | `c2_outage_recovery.csv`, with the sensitivity of the backlog criterion in `c2_backlog_sensitivity.csv` |
| Figure 3 and Table 4, throughput and resources | `c1_phase_summary.json` and `c1_paper_numbers.txt` (file ramps, UDP ramps, Logstash grid, latency), `c1_resources.csv`, `c2_udp_capacity.csv` |
| Figure 4, timelines | runs `p4-out-{a,b,c}-300-r1` and `p6-flood-{a,bdisk,c}-8000-r1` of campaign 1 |
| Table 5 and Figure 5, flooding | `c2_flood.csv`, `c3_factorial_flood.csv`, per stream in `c2_per_stream.csv`, campaign-1 flood windows in `c1_flood_windows.csv` and `c1_flood_summary.json` |
| Table 6, alerts | `c4_kibana_alerts.csv`, `c4_wazuh_alerts.csv` |
| RQ4, cost cell with Kibana | `c3_cost.csv` |
| RQ4, storage per event | `c1_storage.csv` |

## Files

| File | Content | Produced by |
|---|---|---|
| `c1_per_run_metrics.csv` | Loss, duplicates and latency quantiles per run and stream (first receipt per ID) | `campaigns_2_4/reanalyse.py` |
| `c1_outage_recovery.csv` | Recovery after each backend pause | `reanalyse.py` |
| `c1_loss_windows.csv` | Where in the run the missing events fall | `reanalyse.py` |
| `c1_flood_windows.csv` | Attack-stream loss and latency during each flood window | `reanalyse.py` |
| `c1_resources.csv` | Median and maximum CPU and memory per run | `reanalyse.py` |
| `c1_phase_summary.json` | Means and standard deviations per phase and condition | `aggregate.py` |
| `c1_flood_summary.json` | Attack-stream statistics of the campaign-1 floods | `flood_report.py` |
| `c1_paper_numbers.txt` | Every campaign-1 number quoted in the paper | `paper_numbers.py` |
| `c1_storage.csv` | Index size against event count during the 30-minute storage run | `run.py` |
| `c2_flood.csv` | Campaign-2 flooding: loss and p95 latency per run and stream | `derived/paper_evidence.py` |
| `c2_outage_recovery.csv` | Campaign-2 outages: loss, time until the pre-clearance events arrive and catch-up time | `paper_evidence.py` |
| `c2_udp_capacity.csv` | Received rate and backlog of variant A at 4,000 and 6,000 UDP EPS | `paper_evidence.py` |
| `c2_per_stream.csv` | All campaign-2 streams with sent, received, duplicate and missing counts | `paper_evidence.py` |
| `c2_validation.json` | Independent reconciliation of counts, quantiles and recovery points | `paper_evidence.py` |
| `c2_backlog_sensitivity.csv` | Catch-up time under other backlog thresholds | `backlog_sensitivity.py` |
| `c3_factorial_flood.csv` | Campaign-3 flooding of A-topics and A-pipelines | `paper_evidence_e3.py` |
| `c3_cost.csv` | CPU and memory per container in the cost cell with Kibana | `paper_evidence_e3.py` |
| `c4_kibana_alerts.csv` | Alerts per attack event, alert latency and brute-force firings with Kibana rules | `paper_evidence_e5.py` |
| `c4_wazuh_alerts.csv` | The same measures from the Wazuh alert log of campaign 2 | `wazuh_alert_latency.py` |

Metric definitions are in [`../harness/campaigns_2_4/decisions.md`](../harness/campaigns_2_4/decisions.md). Latency ends when the indexer receives the indexing request, quantiles cover only events that arrived, and an event is missing when its ID is absent from the final index scan.
