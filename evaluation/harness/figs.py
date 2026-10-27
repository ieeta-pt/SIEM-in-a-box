"""Paper figures, generated from the raw per-run results (no hand-typed numbers).

Writes PDFs to ../figures/. Colours: validated categorical
palette (A blue, Wazuh orange, B-disk aqua) plus a neutral grey for the
unbuffered reference B; every series also has its own marker and line style
so the figures remain readable in greyscale print.
"""
import glob
import json
import os
import statistics as st
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = os.path.join(os.path.dirname(__file__), "..", "figures")
os.makedirs(OUT, exist_ok=True)
STYLE = {
    "A":     dict(color="#2a78d6", marker="o", ls="-",  label="A: Kafka + Logstash"),
    "C":     dict(color="#eb6834", marker="s", ls="-",  label="C: Wazuh"),
    "Bdisk": dict(color="#1baf7a", marker="^", ls="-",  label="B-disk: disk queue"),
    "B":     dict(color="#6b6b6b", marker="v", ls="--", label="B: memory queue"),
}
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Liberation Serif", "DejaVu Serif"],
    "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8, "legend.fontsize": 7,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "lines.linewidth": 1.4, "lines.markersize": 4.5,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "grid.color": "#dddddd", "grid.linewidth": 0.5, "axes.edgecolor": "#555555",
    "pdf.fonttype": 42,
})


def results(phase):
    for p in glob.glob(os.path.join(os.path.dirname(__file__), "results", "*", "result.json")):
        r = json.load(open(p))
        if r["spec"]["phase"] == phase:
            yield r


def agg(pairs):
    g = defaultdict(list)
    for k, v in pairs:
        g[k].append(v)
    return {k: (st.mean(v), st.stdev(v) if len(v) > 1 else 0.0) for k, v in g.items()}


def line(ax, v, xs, ys, es=None, **kw):
    s = dict(STYLE[v]); s.update(kw)
    if es is not None:
        ax.errorbar(xs, ys, yerr=es, capsize=2, elinewidth=0.8, **s)
    else:
        ax.plot(xs, ys, **s)


# ---------------------------------------------------------------- representative timelines (campaign 1)
def _timeline(run, stream):
    """Per-event view of one run: production time vs latency, plus lost events."""
    import numpy as np
    d = os.path.join(os.path.dirname(__file__), "results", run)
    raw = dict(np.load(os.path.join(d, "raw.npz")))
    m = json.load(open(os.path.join(d, f"gen-{stream}.json")))
    from campaigns_2_4.reanalyse import first_receipts
    ids, produced, received, _ = first_receipts(
        raw["seq"], raw["t_ns"], raw["t_ing"], m["seq_start"], m["seq_end"])
    t = (produced - m["start_ns"]) / 1e9
    lat = (received - produced) / 1e9
    miss = np.setdiff1d(np.arange(m["seq_start"], m["seq_end"]), ids)
    tl = (miss - m["seq_start"]) / m["target_rate"]
    r = json.load(open(os.path.join(d, "result.json")))
    fault = None
    if r.get("fault_ns"):
        fault = [(x - m["start_ns"]) / 1e9 for x in r["fault_ns"]]
    elif r["spec"].get("flood"):
        f = r["spec"]["flood"]; fault = [f["at"], f["at"] + f["dur"]]
    return t, lat, tl, fault


def fig_timeline():
    import numpy as np
    rng = np.random.default_rng(1)
    cols = [("Elasticsearch / indexer paused 5 min (UDP, 500 EPS)", "p4-out-{}-300-r1", "nginx", ("A", "B", "C")),
            ("Attack events during an 8,000 EPS flood", "p6-flood-{}-8000-r1", "auth", ("A", "Bdisk", "C"))]
    fig, axes = plt.subplots(3, 2, figsize=(6.3, 2.8), sharex="col")
    for c, (title, pat, stream, variants) in enumerate(cols):
        for rix, v in enumerate(variants):
            ax = axes[rix][c]
            ts, lat, tl, win = _timeline(pat.format(v.lower()), stream)
            if win:
                ax.axvspan(win[0], win[1], color="#eeeeee", lw=0, zorder=0)
            k = min(len(ts), 2500)
            idx = rng.choice(len(ts), k, replace=False) if len(ts) > k else np.arange(len(ts))
            ax.scatter(ts[idx], np.maximum(lat[idx], 0.01), s=1.5, color=STYLE[v]["color"], lw=0, rasterized=True)
            ax.set_yscale("log")
            ax.set_ylim(0.01, 2000)
            ax.set_yticks([0.1, 10, 1000])
            ax.set_yticklabels(["0.1", "10", "1000"])
            if len(tl):
                ax.scatter(tl, np.full(len(tl), 1300.0), marker="|", s=14, color="#e34948", lw=0.6)
                ax.text(0.99, 0.94, f"{len(tl):,} lost", transform=ax.transAxes, ha="right", va="top",
                        fontsize=6.5, color="#b8322f",
                        bbox=dict(boxstyle="square,pad=0.15", fc="white", ec="none", alpha=0.85), zorder=5)
            ax.text(0.01, 0.94, STYLE[v]["label"], transform=ax.transAxes, ha="left", va="top", fontsize=6.5,
                    color="#222222", bbox=dict(boxstyle="square,pad=0.15", fc="white", ec="none", alpha=0.85), zorder=5)
            if c == 0:
                ax.set_ylabel("Latency (s)")
            if rix == 0:
                ax.set_title(title, loc="left", fontsize=7.5)
        axes[2][c].set_xlabel("Production time (s)")
    fig.tight_layout(h_pad=0.4, w_pad=1.2)
    fig.savefig(os.path.join(OUT, "fig_timeline.pdf"), bbox_inches="tight", dpi=300)


# ================================================================ Confirmatory campaign (campaigns_2_4)
import csv
import numpy as np

REV = os.path.join(os.path.dirname(__file__), "campaigns_2_4")
DERIVED = os.path.join(REV, "derived")
VCOL = {"A-sep": "#2a78d6", "A-pipelines": "#1b9ad6", "A-topics": "#a05bb5", "A-shared": "#7b4fc4",
        "B-disk": "#1baf7a", "C": "#eb6834"}
VNAME = {"A-sep": "A", "A-pipelines": "A-pipe", "A-topics": "A-topic", "A-shared": "A-shared", "B-disk": "B-disk", "C": "C"}


def read_csv(name):
    return list(csv.DictReader(open(os.path.join(DERIVED, name))))


# ---------------------------------------------------------------- flood, per run (E1)
def fig_flood_runs():
    rows = read_csv("paper_e1_exposure.csv") + read_csv("paper_e3_exposure.csv")
    variants = ["A-sep", "A-pipelines", "A-topics", "A-shared", "B-disk", "C"]
    fig, axes = plt.subplots(2, 2, figsize=(6.3, 2.55))
    jitter = {0: -0.17, 6000: 0.17}
    for ri, src in enumerate(("auth", "web")):
        for ci, (key, ylabel) in enumerate((("p95_s", "p95 latency (s, log)"), ("missing_pct", "Lost at final scan (%)"))):
            ax = axes[ri][ci]
            for vi, v in enumerate(variants):
                for fl in (0, 6000):
                    ys = [float(r[key]) for r in rows if r["variant"] == v and r["source"] == src and int(r["flood"]) == fl]
                    xs = [vi + jitter[fl] + d for d in (-0.05, 0.0, 0.05)]
                    ax.scatter(xs, ys, s=22, marker="o" if fl == 0 else "s",
                               facecolors="white" if fl == 0 else VCOL[v], edgecolors=VCOL[v], linewidths=1.0, zorder=3)
            ax.set_xticks(range(len(variants)))
            ax.set_xticklabels([VNAME[v] for v in variants], fontsize=6.5)
            ax.set_xlim(-0.6, len(variants) - 0.4)
            if key == "p95_s":
                ax.set_yscale("log")
                ax.set_ylim(0.15, 900)
            else:
                ax.set_ylim(-1.5, 36)
            ax.set_ylabel(("Attack (sshd) stream\n" if src == "auth" else "Web stream\n") + ylabel, fontsize=7.5)
    axes[0][0].set_title("(a) Latency of events that arrived", loc="left")
    axes[0][1].set_title("(b) Share lost at the final scan", loc="left")
    h = [plt.Line2D([], [], marker="o", ls="", markerfacecolor="white", markeredgecolor="#444444", label="no flood (200 EPS web)"),
         plt.Line2D([], [], marker="s", ls="", color="#444444", label="+6,000 EPS flood on the web source")]
    fig.legend(handles=h, loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.03), fontsize=7)
    fig.tight_layout(rect=(0, 0, 1, 0.95), h_pad=0.6)
    fig.savefig(os.path.join(OUT, "fig_flood_runs.pdf"), bbox_inches="tight")


# ---------------------------------------------------------------- outages, per run (E2)
def fig_outage_runs():
    rows = read_csv("paper_recovery.csv")
    conds = [("A-sep", 500, 60), ("A-sep", 500, 300), ("A-sep", 500, 600), ("A-sep", 2000, 600),
             ("B-disk", 500, 600), ("B-disk", 2000, 600), ("C", 500, 600)]
    labels = [f"{VNAME[v]}, {r:,} EPS, {p} s" for v, r, p in conds]
    fig, axes = plt.subplots(1, 3, figsize=(6.3, 2.0), sharey=True, gridspec_kw=dict(width_ratios=[1.15, 1.15, 0.8]))
    XMAX = 950
    for ci, ax in enumerate(axes):
        for yi, (v, r, p) in enumerate(conds):
            sel = sorted([x for x in rows if x["variant"] == v and int(x["rate"]) == r and int(x["pause_s"]) == p],
                         key=lambda x: int(x["repetition"]))
            dy = [-0.22, 0.0, 0.22]
            for k, x in enumerate(sel):
                y = yi + dy[k]
                if ci == 0:
                    if x["pre_recovery_s"]:
                        ax.scatter(float(x["pre_recovery_s"]), y, s=20, color=VCOL[v], zorder=3)
                    else:
                        ax.scatter(XMAX, y, s=28, marker="x", color=VCOL[v], zorder=3)
                elif ci == 1:
                    if x["catchup_status"] == "observed":
                        ax.scatter(float(x["catchup_s"]), y, s=20, color=VCOL[v], zorder=3)
                    elif x["catchup_status"] == "censored_before_generator_stop":
                        ax.scatter(XMAX, y, s=30, marker=">", facecolors="white", edgecolors=VCOL[v], zorder=3)
                    else:
                        ax.scatter(XMAX, y, s=28, marker="x", color=VCOL[v], zorder=3)
                else:
                    ax.scatter(float(x["missing_pct"]), y, s=20, color=VCOL[v], zorder=3)
        if ci < 2:
            ax.set_xscale("log")
            ax.set_xlim(3, 1300)
            ax.set_xticks([10, 100, 1000])
            ax.set_xticklabels(["10", "100", "1000"])
            ax.axvline(900, color="#bbbbbb", lw=0.6, ls=":")
        else:
            ax.set_xlim(-0.3, 4.8)
    axes[0].set_yticks(range(len(conds)))
    axes[0].set_yticklabels(labels, fontsize=7)
    axes[0].invert_yaxis()
    axes[0].set_title("(a) Pre-pause events all indexed (s)", loc="left", fontsize=7.5)
    axes[1].set_title("(b) Backlog back to baseline (s)", loc="left", fontsize=7.5)
    axes[2].set_title("(c) Lost at final scan (%)", loc="left", fontsize=7.5)
    axes[0].set_xlabel("Seconds after backend ready")
    axes[1].set_xlabel("Seconds after backend ready")
    axes[2].set_xlabel("Percent of events sent")
    h = [plt.Line2D([], [], marker="o", ls="", color="#444444", label="observed, one run"),
         plt.Line2D([], [], marker=">", ls="", markerfacecolor="white", markeredgecolor="#444444", label="not reached when production ended (900 s)"),
         plt.Line2D([], [], marker="x", ls="", color="#444444", label="not reportable: events lost")]
    fig.legend(handles=h, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.5, 1.04), fontsize=7)
    fig.tight_layout(rect=(0, 0, 1, 0.94), w_pad=0.8)
    fig.savefig(os.path.join(OUT, "fig_outage_runs.pdf"), bbox_inches="tight")


# ---------------------------------------------------------------- throughput with backlog panel (campaign 1 + E2)
def fig_throughput():
    fig, (a1, a2, a3) = plt.subplots(1, 3, figsize=(6.3, 1.9))
    p95 = agg(((r["spec"]["variant"], r["spec"]["rate"]), r["streams"]["nginx"]["lat_p95_ms"] / 1000)
              for r in results("ramp"))
    rates = [1000, 2000, 3000, 4000, 6000, 8000]
    for v in ("B", "Bdisk", "A"):
        line(a1, v, [x / 1000 for x in rates], [p95[(v, x)][0] for x in rates])
    a1.set_yscale("log")
    a1.set_xlabel("Offered load (kEPS)")
    a1.set_ylabel("p95 latency (s, log)")
    a1.set_title("(a) Log files, campaign 1", loc="left")
    p95u = agg(((r["spec"]["variant"], r["spec"]["rate"]), r["streams"]["nginx"]["lat_p95_ms"] / 1000)
               for r in results("ramp-udp"))
    ur = [500, 1000, 1500, 2000, 3000, 4000]
    for v in ("C", "A"):
        line(a2, v, [x / 1000 for x in ur], [p95u[(v, x)][0] for x in ur])
    a2.set_yscale("log")
    a2.set_xlabel("Offered load (kEPS)")
    a2.set_title("(b) UDP syslog, campaign 1", loc="left")
    lossv = [r["streams"]["nginx"]["loss_pct"] for r in results("ramp-udp")
             if r["spec"]["variant"] == "C" and r["spec"]["rate"] == 4000]
    a2.annotate(f"Wazuh drops\n{min(lossv):.0f}–{max(lossv):.0f}%", xy=(4, p95u[("C", 4000)][0]), xytext=(2.3, 20),
                fontsize=6.5, arrowprops=dict(arrowstyle="-", color="#777777", lw=0.6))
    # (c) backlog trajectories of the confirmatory UDP capacity runs
    ls_by_rep = {1: "-", 2: "--", 3: ":"}
    col = {4000: "#2a78d6", 6000: "#b23a48"}
    for rate in (4000, 6000):
        for rep in (1, 2, 3):
            p = os.path.join(REV, "new_results", f"rev27-e2-cap-a-sep-{rate}-r{rep}", "backlog-nginx.csv")
            rows = list(csv.DictReader(open(p)))
            xs = [float(r["seconds_from_start"]) for r in rows]
            ys = [int(r["backlog_to_request_receipt"]) / 1000 for r in rows]
            a3.plot(xs, ys, color=col[rate], ls=ls_by_rep[rep], lw=1.1,
                    label=f"{rate:,} EPS" if rep == 1 else None)
    a3.set_xlim(0, 300)
    a3.set_xlabel("Seconds from start")
    a3.set_ylabel("Backlog (thousand events)")
    a3.set_title("(c) A, UDP, campaign 2", loc="left")
    a3.legend(loc="upper left", frameon=False, fontsize=6.5, handlelength=1.6)
    a3.text(295, 12, "6,000 EPS: 5,040\u20135,210\nevents/s reach the indexer", fontsize=6, color=col[6000], ha="right", va="bottom")
    h1, l1 = a1.get_legend_handles_labels()
    h2, l2 = a2.get_legend_handles_labels()
    hl = dict(zip(l1 + l2, h1 + h2))
    ls = [STYLE[v]["label"] for v in ("A", "C", "Bdisk", "B")]
    fig.legend([hl[l] for l in ls], ls, loc="upper center", ncol=4, frameon=False, bbox_to_anchor=(0.5, 1.07), fontsize=7)
    fig.tight_layout(rect=(0, 0, 1, 0.92), w_pad=0.6)
    fig.savefig(os.path.join(OUT, "fig_throughput.pdf"), bbox_inches="tight")


if __name__ == "__main__":
    fig_outage_runs()
    fig_throughput()
    fig_timeline()
    fig_flood_runs()
    print("figures written to", os.path.abspath(OUT))
