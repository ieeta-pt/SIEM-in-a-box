# Campaign 1: testbed, decisions and anomalies

Every methodological decision and every anomaly found while building and
validating the harness and running campaign 1, with its diagnosis. Campaigns
2 to 4 follow `campaigns_2_4/PRE-RUN-PROTOCOL.md` and the metric definitions
in `campaigns_2_4/decisions.md`.

## Testbed
- Single laptop host: Intel i7-13700H (6P+8E cores, 20 threads), 31 GB RAM,
  NVMe SSD with LUKS + btrfs (zstd). Docker 29.7.
- SUT ("8-vCPU SIEM host") pinned to CPUs 0-7 (four P-cores, both threads).
  Generator and collectors ("source hosts") pinned to CPUs 12-19 (E-cores).
- Elastic 8.19.7 (ES heap 3 GB), Kafka 3.9 KRaft single broker (heap 1 GB),
  Logstash 8.19.7 (heap 1 GB), Filebeat 8.19.7, Wazuh 4.14.5 (indexer heap
  3 GB). Security/TLS disabled on the Elastic variants (benchmark); Wazuh
  runs its stock TLS.
- Host condition logged every 30 s (results/host.csv): package temperature,
  CPU MHz, cumulative thermal-throttle counters, IO pressure. The laptop
  throttles under sustained load (>116k package throttle events at start).

## Measurement method
- Every event carries `bseq=<seq>:<t_produce_ns>`; a final ingest pipeline
  (identical on Elasticsearch and on the Wazuh/OpenSearch indexer) stamps the
  ingest time, so latency = produce-to-ingest (excludes the 1 s refresh).
- Loss/duplicates are exact: every indexed event is read back (scroll over
  doc values) and compared with the generator's sequence range.
- Two source classes: `file` (host log tailed by the collector, cannot lose
  events at the source) and `udp` (syslog appliance, cannot be throttled:
  backpressure becomes real loss). A throttled generator therefore cannot
  hide loss.
- Each run uses a unique sequence range (time-based), so runs never collide
  even when they share an index (Wazuh archives).

## Decisions taken during validation (with evidence)
1. **Collector read backoff.** With Filebeat defaults (filestream
   `backoff.init: 2s`), events arrived in batches exactly every 2.000 s and
   latency was a 0.3-3.5 s sawtooth caused by collector polling. All
   variants use `backoff.init: 250ms`, `backoff.max: 1s`. One sensitivity
   run per variant keeps the defaults (`collector_defaults`).
2. **Collector memory queue.** With `flush.min_events: 512` +
   `flush.timeout: 1s`, Filebeat kept a residue of ~300 events that the
   timeout did not release; at the end of a run, 245 events were never
   sent. All memory-queue collectors now use `flush.min_events: 0` (events
   immediately available to the output; the output still batches).
   Verified: received = acked = indexed in 5/5 validation runs.
3. **End-of-run tail.** Latency statistics exclude the first `warmup`
   seconds and the last 5 s of production (cool-down), so collector
   back-off at end of stream does not inflate percentiles.
4. **Steady-state latency around faults.** "Pre-fault" uses events
   produced >= 10 s before the fault; "post-fault" uses events produced
   >= 10 s after recovery. Events in flight when the fault starts are
   excluded from both and reported as fault-window latency.
5. **Wazuh background modules.** On first start, Wazuh's vulnerability
   detector downloaded and unpacked its CVE feed: the manager wrote 22.9 GB
   in minutes, IO pressure reached 45 % "full", and fsync latency rose
   from 1.3 ms to 40 ms for every container on the host. Modules unrelated
   to log analysis (vulnerability detection, FIM/syscheck, rootcheck, SCA,
   syscollector) are disabled for the benchmark. Log analysis (remoted,
   analysisd, archives) is unchanged.
6. **Wazuh measurement hook.** Wazuh's archives ingest pipeline reroutes
   documents (`date_index_name`), so an index `final_pipeline` never runs.
   The identical `bench-final` processors are appended to Wazuh's archives
   pipeline instead.
7. **Wazuh index cleanup race.** Deleting the archives index at run start
   caused 50 `index_not_found` rejections in Wazuh's Filebeat. The
   archives index is never deleted while Wazuh runs; runs are separated by
   sequence ranges.
8. **Wildcard deletes.** ES 8 blocks wildcard index deletion by default
   (`action.destructive_requires_name`); without enabling it, per-run
   cleanup silently failed. Enabled in es_setup.py.
9. **Index-name case.** Filebeat lowercases index names; run ids are
   lowercased.

10. **Drain criterion with duplicates.** "count >= n_sent" was reached
    before the last unique events were indexed when duplicates were present
    (A, 10-min outage: 4 trailing events missed, all acked by Filebeat).
    Drain now also requires the count to be stable for 15 s. Run redone.
11. **Uncontrolled CPU frequency (UDP ramp, first attempt).** In repetition 1
    of the UDP ramp the SUT cores were hard-capped at 2.2 GHz (unknown power
    limit), in repetition 2 they reached 3.0-4.2 GHz; throughput ceilings
    differed accordingly (Wazuh ~1,000 vs ~1,900 EPS). All 23 runs discarded.
    From then on Turbo Boost is disabled (fixed base frequency) and the
    charger must be connected; session.sh refuses to start otherwise, and
    host.csv logs no_turbo and AC state every 30 s. The ramp, grid,
    outage-load, outage-file and storage phases ran with Turbo off. The
    outage, Kafka-kill, latency and flood phases ran before this change:
    their conclusions do not depend on CPU speed (loss, durability), or the
    speed difference favoured the baseline (flood: Wazuh runs had higher
    peak MHz than A).

## Behaviours observed
- **Broker crash recovery (A).** After a 30 s SIGKILL of Kafka, the broker
  needed ~14 s to restart (KRaft log recovery) and Filebeat reconnected
  ~17 s later (client backoff): UDP events were lost for ~61 s in total,
  about twice the outage. 1,505 duplicates came from in-flight batches
  re-sent after reconnection (at-least-once).
- **Duplicates on backend recovery (A).** Logstash re-sends in-flight bulk
  requests when Elasticsearch freezes, producing ~1 % duplicates around the
  start of a long outage.
- **B ingest stalls.** Variant B (Filebeat -> ES ingest pipeline) shows
  intermittent 2-6 s stalls (several per 3 min at 500 EPS) during which
  Filebeat has a bulk request outstanding and Elasticsearch reports no
  indexing activity; not caused by GC (pauses ~3 ms) or by output
  serialisation (persists with 2 output workers). Variant A, whose events
  arrive pre-parsed from Logstash, shows none (max 1.02 s over 56k events).
  Affects B's p99, not p50/p95, loss or durability. Root cause not isolated.
- **Flood isolation (smoke test, 1 run).** Under a 40 s 4,000 EPS flood on
  the web source, attack events on the auth source had p95 72.8 s in Wazuh
  (shared analysisd queue) vs 1.1 s in A (per-source topic and pipeline).

## Discarded runs
Runs collected with the residue-prone queue setting (decision 2) and the 23
runs with uncontrolled CPU frequency (decision 11) are not counted in the 193
campaign-1 runs. They are kept in the raw-records archive under
`results/_discarded/`.
