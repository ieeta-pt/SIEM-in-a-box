"""Flooding runs: what happens to the attack (auth) stream DURING the flood."""
import glob, json, os
import numpy as np


def window_stats(d, m, mask_auth, w0, w1):
    lo, hi = m["seq_start"], m["seq_end"]
    sel = (d["seq"] >= lo) & (d["seq"] < hi)
    seq, tns, ting = d["seq"][sel], d["t_ns"][sel], d["t_ing"][sel]
    rate = m["target_rate"]
    t = (np.arange(lo, hi) - lo) / rate                       # production offset of every emitted seq
    inwin = (t >= w0) & (t < w1)
    expected = np.arange(lo, hi)[inwin]
    got = np.intersect1d(expected, seq)
    tp = (tns - m["start_ns"]) / 1e9
    lat = (ting - tns)[(tp >= w0) & (tp < w1)] / 1e6
    return {"sent": int(len(expected)), "lost_pct": 100 * (1 - len(got) / len(expected)) if len(expected) else float("nan"),
            "p50_ms": float(np.percentile(lat, 50)) if len(lat) else float("nan"),
            "p95_ms": float(np.percentile(lat, 95)) if len(lat) else float("nan"),
            "max_ms": float(lat.max()) if len(lat) else float("nan")}


def main():
    rows = []
    for p in sorted(glob.glob("results/p6-flood-*/result.json")):
        r = json.load(open(p)); d = dict(np.load(os.path.join(os.path.dirname(p), "raw.npz")))
        fl = r["spec"]["flood"]; w0, w1 = fl["at"], fl["at"] + fl["dur"]
        ma = json.load(open(os.path.join(os.path.dirname(p), "gen-auth.json")))
        a = window_stats(d, ma, None, w0, w1)
        out = {"id": r["id"], "variant": r["spec"]["variant"], "flood": fl["rate"], "auth": a}
        if os.path.exists(os.path.join(os.path.dirname(p), "gen-flood.json")):
            mf = json.load(open(os.path.join(os.path.dirname(p), "gen-flood.json")))
            out["flood_lost_pct"] = r["streams"]["flood"]["loss_pct"]
        rows.append(out)
        print(f"{r['id']:24s} flood={fl['rate']:5d}  ATTACK during flood: sent={a['sent']:4d} lost={a['lost_pct']:6.2f}% "
              f"p50={a['p50_ms']:8.0f} p95={a['p95_ms']:8.0f} max={a['max_ms']:8.0f} ms"
              + (f" | flood stream lost={out['flood_lost_pct']:.2f}%" if "flood_lost_pct" in out else ""))
    json.dump(rows, open("results/flood_summary.json", "w"), indent=1)


if __name__ == "__main__":
    main()
