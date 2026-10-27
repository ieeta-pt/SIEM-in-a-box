"""Exact per-run analysis: loss, duplicates, latency, throughput, recovery.

Reads every indexed benchmark event (no sampling or approximate
aggregations) through a point-in-time + search_after scan of doc values,
then compares them with the generator manifest.
"""
import numpy as np
import requests


def session(es):
    s = requests.Session()
    if es.startswith("https://localhost:9201"):        # Wazuh indexer (variant C)
        s.auth = ("admin", "SecretPassword")
        s.verify = False
        requests.packages.urllib3.disable_warnings()
    return s


def fetch(es, index, query=None):
    """Return seq, t_ns, t_ingest_ns (int64) and src (bool: auth) arrays.

    Uses the scroll API (supported identically by Elasticsearch and by the
    OpenSearch-based Wazuh indexer), reading doc values only.
    """
    s = session(es)
    seq, tns, ting, auth = [], [], [], []
    body = {
        "size": 10000,
        "_source": False,
        "docvalue_fields": ["bench.seq", "bench.t_ns", "bench.t_ingest_ns", "bench.src"],
        "query": query or {"exists": {"field": "bench.seq"}},
        "sort": ["_doc"],
    }
    r = s.post(f"{es}/{index}/_search?scroll=5m", json=body)
    if r.status_code == 404:
        return {k: np.zeros(0, dtype=np.int64) for k in ("seq", "t_ns", "t_ing")} | {"auth": np.zeros(0, bool)}
    r.raise_for_status()
    js = r.json()
    sid = js.get("_scroll_id")
    while True:
        hits = js["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            f = h["fields"]
            seq.append(f["bench.seq"][0])
            tns.append(f["bench.t_ns"][0])
            ting.append(f["bench.t_ingest_ns"][0])
            auth.append(f["bench.src"][0] == "auth")
        r = s.post(f"{es}/_search/scroll", json={"scroll": "5m", "scroll_id": sid})
        r.raise_for_status()
        js = r.json()
        sid = js.get("_scroll_id", sid)
    s.delete(f"{es}/_search/scroll", json={"scroll_id": sid})
    return {"seq": np.array(seq, dtype=np.int64), "t_ns": np.array(tns, dtype=np.int64),
            "t_ing": np.array(ting, dtype=np.int64), "auth": np.array(auth, dtype=bool)}


def pct(x, q):
    return float(np.percentile(x, q)) if len(x) else float("nan")


def summarize(d, manifest, warmup_s=0.0, fault=None, cooldown_s=5.0):
    """Summarise one event stream against its generator manifest.

    fault: optional (start_ns, end_ns) of an injected fault, used for
    recovery time (time after the fault clears until every event produced
    up to the clearance instant has been indexed).
    """
    n_sent = manifest["n_sent"]
    lo, hi = manifest["seq_start"], manifest["seq_end"]
    m = (d["seq"] >= lo) & (d["seq"] < hi)
    seq, tns, ting = d["seq"][m], d["t_ns"][m], d["t_ing"][m]
    uniq = np.unique(seq)
    n_idx, n_uniq = len(seq), len(uniq)
    lat = (ting - tns) / 1e6
    t0 = manifest["start_ns"] + int(warmup_s * 1e9)
    t1 = manifest["end_ns"] - int(cooldown_s * 1e9)
    sel = (tns >= t0) & (tns <= t1)
    lw = lat[sel]
    out = {
        "n_sent": n_sent, "n_indexed": int(n_idx), "n_unique": int(n_uniq),
        "loss_pct": 100.0 * (1 - n_uniq / n_sent) if n_sent else float("nan"),
        "dup_pct": 100.0 * (n_idx - n_uniq) / n_sent if n_sent else float("nan"),
        "achieved_rate": manifest["achieved_rate"],
        "lat_p50_ms": pct(lw, 50), "lat_p90_ms": pct(lw, 90), "lat_p95_ms": pct(lw, 95),
        "lat_p99_ms": pct(lw, 99), "lat_max_ms": float(lw.max()) if len(lw) else float("nan"),
        "lat_mean_ms": float(lw.mean()) if len(lw) else float("nan"),
    }
    # Latency trend: p95 of the first vs last third of the measurement window
    # (a growing backlog shows up as a rising p95, even with zero loss).
    if len(lw) > 300:
        order = np.argsort(tns[sel])
        thirds = np.array_split(lw[order], 3)
        out["lat_p95_first_third_ms"] = pct(thirds[0], 95)
        out["lat_p95_last_third_ms"] = pct(thirds[-1], 95)
    # Ingest throughput over the measurement window (events produced after
    # warm-up, divided by the span of their ingest times).
    if sel.sum() > 1:
        # events produced in the window / span of their ingest instants
        span = (np.percentile(ting[sel], 99.5) - np.percentile(ting[sel], 0.5)) / 1e9
        out["ingest_rate"] = float(0.99 * sel.sum() / span) if span > 0 else float("nan")
    if fault is not None and len(tns):
        fs, fe = fault
        before = tns <= fe
        out["recovery_s"] = float(max(0.0, (ting[before].max() - fe) / 1e9)) if before.any() else float("nan")
        during = (tns >= fs) & (tns <= fe)
        out["lat_p95_during_fault_ms"] = pct(lat[during], 95)
        # loss restricted to events produced during the fault window: the
        # generator emits at a constant rate, so a missing seq maps to its
        # production instant exactly enough (+/- one 5 ms tick)
        rate = manifest["target_rate"]
        missing = np.setdiff1d(np.arange(lo, hi, dtype=np.int64), uniq, assume_unique=True)
        t_miss = manifest["start_ns"] + (missing - lo) / rate * 1e9
        expected = rate * (fe - fs) / 1e9
        out["lost_during_fault"] = int(((t_miss >= fs) & (t_miss <= fe)).sum())
        out["lost_outside_fault"] = int(len(missing) - out["lost_during_fault"])
        out["loss_during_fault_pct"] = 100.0 * out["lost_during_fault"] / expected if expected else float("nan")
        # steady state, excluding events in flight when the fault began and
        # the post-fault backlog: before = produced >= 10 s before the fault;
        # after = produced >= 10 s after recovery completed
        rec_end = fe + out["recovery_s"] * 1e9 if out["recovery_s"] == out["recovery_s"] else fe
        pre = sel & (tns <= fs - 10e9)
        post = sel & (tns >= rec_end + 10e9)
        out["lat_p95_pre_fault_ms"] = pct(lat[pre], 95)
        out["lat_p95_post_fault_ms"] = pct(lat[post], 95)
        out["lat_p95_outside_fault_ms"] = pct(lat[pre | post], 95)
    return out


def save_raw(path, d):
    """Compact raw record of every indexed event (published with the artifact)."""
    np.savez_compressed(path, seq=d["seq"], t_ns=d["t_ns"], t_ing=d["t_ing"], auth=d["auth"])
