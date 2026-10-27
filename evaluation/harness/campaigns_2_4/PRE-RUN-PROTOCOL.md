# Frozen protocol of campaign 2

English translation of the protocol frozen on 20 October 2026, before the confirmatory runs. The protocol was reviewed after 13 pilot runs, whose decisions are recorded in `PILOT-REVIEW.json`. `protocol_lock.json` validates the pilot artifacts and the run matrix in `campaign_ready.json`. One invalid execution was preserved and repeated with identical parameters under a new ID, as documented in `replacement_plan.json`. Campaigns 3 and 4 follow the same rules, with their own matrices and locks (`campaign_factorial.json` with `factorial_lock.json`, and `campaign_alerts.json` with `alerts_lock.json`).

## Question and metrics

The study compares the preservation of evidence under load and after a backend pause. A-sep (variant A in the paper) and A-shared have equivalent parsers and processing budgets, but the contrast changes topic separation and pipeline separation together and does not identify the effect of each mechanism alone. B-disk and C (Wazuh) are descriptive comparators with different processing paths.

`bench.t_ingest_ns` is the time at which the indexer receives the indexing request. It does not measure search availability, final durability or time to alert. The reception denominator contains only IDs with `sent_ok=1`, and failed send attempts are reported separately. The raw records keep every receipt. Latency and backlog use the **first receipt per ID**, and duplicates are counted separately. p50, p95, p99 and the maximum are reported, and p95 is never called the worst case. `n_missing_at_cutoff` means absent at the end of observation, not confirmed permanent loss. UDP counter deltas and sender failures are complementary evidence, without causal attribution per ID.

The drain compares the distinct IDs sent successfully with those received, waits 30 s and confirms again. If it times out, the snapshot is saved as `timed_out_incomplete`, and no loss is inferred from a plateau. In the pause runs, `pre_clearance.recovery_s` is the time until all IDs produced before clearance have arrived, and `catchup_steady_s` is the first point, during production, at which the backlog stays below the pre-fault median plus `max(50, ceil(0.1 × EPS))` for 31 samples of 1 s. If this is not observed, the value is reported as censored. These are different results.

## Pilot decisions

The local generator test at 8,000 EPS achieved about 7,998.6 EPS with or without per-attempt logging, and the generator CPU rose by about 15.95%. This does not measure SIEM capacity. In the 60 to 180 s window, the A-sep pilot at 4,000 EPS received about 4,000 EPS, with a backlog increase of 14 and no UDP errors, and at 6,000 EPS it received about 5,034 EPS, with a backlog increase of 115,875 and no UDP errors. The 8,000 EPS pilot had 5,274 `RcvbufErrors`, 62,228 IDs missing at cutoff and a drain timeout, so it remains exploratory and does not estimate service capacity with clean input. The long A-sep pilot with a 600 s pause observed pre-clearance recovery at 96.555 s and a return to the normal regime at 138.963 s, so the 900 s of production after clearance were sufficient in that case, without a guarantee for other treatments.

E1 uses **6,000 extra nginx EPS** over a base of 200 EPS and 10 EPS of auth, compared with the same streams without flood. The four E1 pilots showed different behaviours, including UDP errors and IDs missing at cutoff in some treatments. The confirmatory contrast is therefore **evidence preservation along the full path**, not a capacity test with clean input. p95 conditional on receipt is analysed together with input errors, missing IDs and censoring. No single pilot establishes a treatment effect. `PILOT-REVIEW.json` holds the values and limitations per variant.

| Phase | Cells | Nominal production |
|---|---:|---:|
| E1: 4 variants × without/with flood × 3 repetitions | 24 | 2 h |
| E2 capacity: A-sep at 4,000/6,000 EPS × 3 | 6 | 0.5 h |
| E2 pause: 7 conditions × 3 | 21 | 8.4 h |

Total: **51 runs and 10.9 h of production**, plus start-up and drain. The interleaved order is frozen in `campaign_ready.json`. The executor does not modify this matrix and does not analyse effects. Results are written to `new_results/<run_id>/`, always with unique IDs, and the campaign-1 results in `results/` are never modified.

## Validity and host conditions

The runner assesses the execution before any scientific interpretation. A run is invalidated and preserved if more than 5% of the expected telemetry is missing, AC power or Turbo changes, the attempt rate deviates by more than 5% from the offered rate, the wall-to-monotonic clock offset varies by more than 5 ms (p99 to p1), the CPU frequency is missing, the parser fails or index routing crosses sources. Sender and UDP errors, duplicates, missing at cutoff, drain timeouts and thermal flags are **flagged**, not excluded automatically in favour of a hypothesis. An invalid or partial execution blocks the session and requires review and a new ID, and the executor never overwrites a run directory.

`campaign_session.py` checks the lock, Docker, AC power, Turbo, temperature (below 80 °C before the run), free disk (at least 20 GiB), frequency and the availability of CPUs 0 to 7 and 12 to 19. It reserves CPUs 0 to 7 for the SUT and 12 to 19 for the generators, temporarily moves the user's processes to CPUs 8 to 11, and saves and restores their affinities. A 15 s window detects concurrent load or thermal throttling. During each run it reports progress every 30 s and flags AC or Turbo changes, temperatures of 90 °C or more, thermal throttling, less than 10 GiB of free disk, foreign containers and user tasks on the SUT CPUs. On an anomaly it finishes **the current run** to preserve its data and stops before the next one. It records frequency telemetry, since Turbo off does not imply a fixed frequency, and the comparison of frequency and temperature across treatments belongs to the later analysis.

If Turbo is on at the start, the script asks for the `sudo` password once, turns Turbo off, keeps the authorization during the session and tries to restore the original value at the end. No other benchmark runs during the campaign. Ctrl-C stops the session after the current run, and an abrupt interruption requires manual inspection. Logs, `progress.jsonl` and `summary.json` are written to `new_results/campaign-session-<date>/`, and the script stops the stacks at the end.

## Commands

From the harness directory, the listing command is read-only:

```bash
./session.py list
```

The number in the first column selects **a single run**, for example:

```bash
./session.py 9
```

Several increasing numbers run a sequential batch, one run at a time:

```bash
./session.py 9 10 11 12
```

Each run has its own preflight, CPU reservation, idle guard, progress feedback every 30 s, result and cleanup. The batch waits 90 s between pending runs and stops on failure, invalid execution or an interruption request, in which case it does not start the following positions. The numbers and any positions already invalid are validated before the batch starts, and a position that is already valid is reported and skipped. The time estimate covers generation, maximum drain and pauses, **plus** start-ups, and is not a guaranteed limit. A partial or invalid run is never repeated automatically and requires review and a new ID. Non-Wazuh indices are deleted only after the raw records, results and assessment are saved, and old Wazuh archives are not cleaned by the runner.
