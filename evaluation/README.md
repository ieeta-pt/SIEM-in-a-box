# Evaluation

This directory holds the evaluation of *SIEM-in-a-Box: Affordable and Resilient Security Monitoring for Small and Medium Enterprises*: four campaigns, 269 runs and 179 million accounted events on one CPU-pinned host. The sections below summarize the result of each research question, and every number can be traced to a derived table and from there to the runs that produced it.

| Directory | Content |
| --- | --- |
| [`figures/`](figures/) | The four result figures of the paper. |
| [`tables/`](tables/) | The derived tables behind every number in the paper, with a map from each table and figure to its files. |
| [`runs/`](runs/) | The result of every run, one file per campaign, and [`index.csv`](runs/index.csv) with the conditions and status of all 269 runs. |
| [`harness/`](harness/) | The code that ran the campaigns and produced the tables and figures, with the frozen protocols and how to reproduce them. |

## Campaigns

| Campaign | Runs | Purpose | Protocol |
| --- | ---: | --- | --- |
| 1 | 193 | Characterization of A, B, B-disk and C: throughput, latency, backend outages, Kafka kills, flooding and storage. | exploratory, [`harness/campaign.json`](harness/campaign.json) |
| 2 | 51 | Confirmatory flooding of A, A-shared, B-disk and C, UDP capacity of A, and backend outages with exact per-event accounting. | frozen, [`harness/campaigns_2_4/PRE-RUN-PROTOCOL.md`](harness/campaigns_2_4/PRE-RUN-PROTOCOL.md) |
| 3 | 13 | Factorial flooding of A-topics and A-pipelines, and one cost cell with Kibana. | frozen, `campaign_factorial.json` and `factorial_lock.json` |
| 4 | 12 | End-to-end alerts with Kibana detection rules for A and A-shared, with and without flood. | frozen, `campaign_alerts.json` and `alerts_lock.json` |

## Configurations and measurements

| Name | Ingestion path |
| --- | --- |
| A | Kafka topic and Logstash pipeline per source (SIEM-in-a-Box push path). |
| A-shared | One Kafka topic and one Logstash pipeline shared by both sources. |
| A-topics | Separate Kafka topics and one shared Logstash pipeline. |
| A-pipelines | One shared Kafka topic and separate Logstash pipelines; each reads the whole topic and discards events from the other source. |
| B | Filebeat memory queue and Elasticsearch ingest pipeline, without Kafka or Logstash. |
| B-disk | B with a 2 GB Filebeat disk queue. |
| C | Single-node Wazuh, with full archiving enabled. |

The four Kafka configurations form the controlled topology comparison with equal worker budgets. B, B-disk and C perform different work per event and are descriptive comparators. *Loss* means an event identifier was absent from the final index scan. *Indexing latency* ends when the indexer receives the indexing request; it does not measure when an analyst sees an event. Except where stated, p95 values refer only to events that arrived.

## RQ1: Buffering and recovery during backend outages

Across 25 outage runs involving 21.3 million events, A lost no events from UDP sources during backend pauses of up to ten minutes. C also lost none, but recovered more slowly: after a ten-minute pause at 500 events/s, events produced before the backend became ready took 217–242 s to reach the indexer in C, compared with 95–97 s in A (Campaign 2). B lost most events produced during the pause when its memory queue filled. B-disk protected events during the pause but lost up to 4.2% of a run at 2,000 events/s while catching up, matched by collector kernel receive-buffer errors. With a file source, A and B both lost no events; B recovered in 42 s versus 100 s for A in the reported comparison.

**Interpretation:** buffering between collection and indexing helped sources that cannot pause or retry, such as UDP syslog. For a tailed file, the source file itself supplied the buffer. See [backend outage results](figures/fig_outage_runs.pdf) and the [representative timeline](figures/fig_timeline.pdf).

## RQ2: Sustainable throughput and bottleneck

| Source and configuration | Sustainable offered load | Processing capacity under overload |
| --- | ---: | ---: |
| File, A | 3,000 events/s | 4,955 ± 70 events/s |
| File, B | 3,000 events/s | 7,326 ± 67 events/s |
| File, B-disk | 3,000 events/s | 6,681 ± 173 events/s |
| UDP, A | 4,000 events/s | 5,042–5,209 events/s at 6,000 offered |
| UDP, C | 1,500 events/s | 1,522 ± 95 events/s |

At 1,000 events/s from a file, A's median indexing latency was 150 ms and B's was 144 ms. In the Logstash configuration grid, one worker processed about 2,700 events/s with either one or four Kafka partitions; four workers processed the full 6,000 events/s with one partition. **Interpretation:** Logstash parsing workers, rather than Kafka partition count, set the tested buffered path's throughput ceiling. B had the higher capacity for file input; A sustained more UDP traffic than C in the measured configuration. See [throughput figure](figures/fig_throughput.pdf).

## RQ3: Attack visibility during log flooding

Campaigns 2 and 3 ran three repetitions of six configurations with and without an additional 6,000 web events/s, 36 runs in total. Loss and p95 indexing latency of both streams in every run are in [`tables/c2_flood.csv`](tables/c2_flood.csv) and [`tables/c3_factorial_flood.csv`](tables/c3_factorial_flood.csv), and the [flooding figure](figures/fig_flood_runs.pdf) plots them.

| Configuration during flood | Attack-stream loss | Attack-stream p95 indexing latency across three runs |
| --- | ---: | ---: |
| A | 0% | 0.30, 0.30, 0.30 s |
| A-pipelines | 0% | 0.02, 0.02, 0.02 s |
| A-topics | 0% | 0.94, 1.24, 0.63 s |
| A-shared | 0% | 1.85, 9.03, 9.70 s |
| B-disk | 0% | 1.38, 0.82, 1.58 s; web-stream loss 6.3–8.7% |
| C (Wazuh) | 13.8–16.6% | 375, 381, 359 s for events that arrived |

The factorial comparison attributes attack-stream isolation to **separate Logstash pipelines**, not merely separate topics. A-pipelines had the lowest measured attack latency, but each pipeline read and discarded the other source's events, increasing broker and consumer work. A combines isolation with a topic and pipeline per source. In the alert experiment, all 2,999 tested attack events raised Kibana alerts in every A and A-shared run; p95 production-to-alert latency was 62 s for A under flood and 63–65 s across A-shared runs. In the Wazuh comparison, 13.8–16.7% of tested attack events did not raise an alert under flood. The systems use different alert engines and schedules, so alert latency is not a controlled cross-product comparison.

## RQ4: Resource cost and broker failure

At 1,000 file events/s, A used 0.48 CPU cores and 5.70 GiB of resident memory in the measured ingestion containers; B used 0.13 cores and 3.99 GiB. The buffered path thus added approximately **0.35 cores and 1.7 GiB** in that comparison. A separate cost cell with Kibana used 0.50 cores and 6.6 GiB at 1,000 UDP events/s; Fleet Server and the secured alerting node were not profiled.

The single broker is a failure point for UDP senders. Killing Kafka for one or ten minutes at 500 events/s lost 36.3 ± 2.4% or 80.9 ± 2.9% of events in the full four- or thirteen-minute runs, respectively. Loss continued for 20–65 s after restart. Default Elasticsearch mapping used about 793 bytes of index storage per event in the measured storage run.

**Interpretation:** A trades memory, CPU, storage and broker availability for protection against backend pauses and for source isolation. The lower-cost B path is useful when the source already persists its events.

## Runs

[`runs/index.csv`](runs/index.csv) lists all 269 runs with their campaign, variant, source, rate, fault, flood and status. The full result of each run is in `runs/campaign-<n>.json`, keyed by run ID, with three parts:

| Key | Content |
| --- | --- |
| `result` | The run specification (`spec`) and its analysis: sent, received, duplicate and missing events, latency quantiles, recovery, container resource use and, for campaigns 2 to 4, the UDP kernel counters and the alert summary. |
| `generators` | The manifest of each generator stream: sequence range, sent events, send errors and achieved rate. |
| `execution_assessment` | The validity checks of the frozen protocol and their outcome (campaigns 2 to 4). |

Run IDs encode the condition. Campaign 1 uses `p<phase>-<kind>-<variant>-<parameter>-r<repetition>` (`p4-out-a-300-r1` is a 300 s backend pause of variant A), and campaigns 2 to 4 use `rev27-e<experiment>-<variant>-...-r<repetition>` (`rev27-e1-a-shared-f6000-r2` is A-shared under a 6,000 EPS flood). Variant `a-sep` is variant A of the paper.

Campaign-1 runs report `complete_id_set_at_scan` or `incomplete_id_set_at_scan` as status, depending on whether every sent event was in the final index scan. Campaigns 2 to 4 report `complete`, or `timed_out_incomplete` when events were still missing when the drain timed out. One campaign-2 run (`rev27-e1-c-f6000-r1`) failed a validity check and was repeated under a new ID with identical parameters, as the protocol prescribes. Only the repetition is counted and listed.

## Raw per-event records

The raw records, with every indexed event (`raw.npz`) and every send attempt (`gen-<stream>.events.bin`), total 3.2 GB and are distributed as a separate archive with SHA-256 checksums. The archive also holds the per-second time series of every run (send rate, backlog, container CPU and memory), the configuration hashes, every Kibana alert, the collector and generator logs, the host telemetry, the pilot runs and the console logs of every session. [`harness/README.md`](harness/README.md) explains how to extract it and regenerate the tables and figures.
