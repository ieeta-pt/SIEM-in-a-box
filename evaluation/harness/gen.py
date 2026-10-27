"""Load generator for the SIEM-in-a-Box measurement campaign.

Emits synthetic events at a constant target rate, each carrying a unique
sequence number and its production time (``bseq=<seq>:<t_ns>``), so the
analyser can compute exact loss, duplicates and per-event latency.

Two source classes:
  file  - appends to a log file that a collector tails (host logs). A file
          never blocks the producer, so every line counts as emitted.
  udp   - sends one datagram per event (syslog appliances). UDP cannot be
          throttled by the receiver, so backpressure turns into real loss.

Two event kinds:
  nginx - nginx combined access-log line (the parsing workload).
  auth  - sshd "Failed password" line (attack stream for flooding runs).

Writes <out>.json (counts, achieved rate) and <out>.rate.csv (per second).
"""
import argparse
import hashlib
import json
import random
import socket
import struct
import time

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "curl/8.5.0",
    "python-requests/2.31.0",
]
PATHS = ["/", "/index.html", "/login", "/api/v1/items", "/static/app.js", "/shop/cart", "/search"]
STATUS = [200] * 8 + [301, 304, 401, 403, 404, 500]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def nginx_line(seq, tns, rnd):
    tm = time.gmtime(tns // 1_000_000_000)
    ts = f"{tm.tm_mday:02d}/{MONTHS[tm.tm_mon - 1]}/{tm.tm_year}:{tm.tm_hour:02d}:{tm.tm_min:02d}:{tm.tm_sec:02d} +0000"
    ip = f"10.{rnd.randrange(256)}.{rnd.randrange(256)}.{rnd.randrange(1, 255)}"
    path = rnd.choice(PATHS)
    return (f'{ip} - - [{ts}] "GET {path}?bseq={seq}:{tns} HTTP/1.1" '
            f'{rnd.choice(STATUS)} {rnd.randrange(200, 20000)} "-" "{rnd.choice(UAS)}"')


def auth_line(seq, tns, rnd):
    tm = time.gmtime(tns // 1_000_000_000)
    ts = f"{MONTHS[tm.tm_mon - 1]} {tm.tm_mday:2d} {tm.tm_hour:02d}:{tm.tm_min:02d}:{tm.tm_sec:02d}"
    user = rnd.choice(["admin", "root", "test", "oracle", "ubuntu"])
    return (f"{ts} web01 sshd[{rnd.randrange(1000, 65000)}]: Failed password for invalid user {user} "
            f"from 203.0.113.{rnd.randrange(1, 255)} port {rnd.randrange(1024, 65535)} ssh2 bseq={seq}:{tns}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["file", "udp"], required=True)
    ap.add_argument("--kind", choices=["nginx", "auth"], default="nginx")
    ap.add_argument("--rate", type=float, required=True, help="events per second")
    ap.add_argument("--duration", type=float, required=True, help="seconds")
    ap.add_argument("--file", help="output log file (file mode)")
    ap.add_argument("--host", help="UDP destination host")
    ap.add_argument("--port", type=int, help="UDP destination port")
    ap.add_argument("--out", required=True, help="manifest path prefix")
    ap.add_argument("--seq-start", type=int, default=0)
    ap.add_argument("--start-at", type=float, default=0.0, help="wall-clock start time (epoch s)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--events-out", help="revision: packed per-attempt binary event log")
    a = ap.parse_args()

    rnd = random.Random(a.seed)
    make = nginx_line if a.kind == "nginx" else auth_line
    fh = sock = events_fh = None
    if a.mode == "file":
        fh = open(a.file, "a", buffering=1 << 20)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 << 20)
        dest = (a.host, a.port)
    if a.events_out:
        events_fh = open(a.events_out, "wb", buffering=8 << 20)
    event_record = struct.Struct("<qqqB")

    if a.start_at:
        while time.time() < a.start_at:
            time.sleep(min(0.05, max(0.0, a.start_at - time.time())))

    tick = 0.005
    seq = a.seq_start
    sent = 0
    send_errors = 0
    per_sec = {}
    t0 = time.monotonic()
    wall0 = time.time_ns()
    end = t0 + a.duration
    while True:
        now = time.monotonic()
        if now >= end:
            break
        due = int(a.rate * (now - t0)) - sent
        if due > 0 and events_fh is not None:
            # The line and its record share the *same* production timestamp.
            # Record every attempt, including a failed UDP send. One buffered
            # write per generator tick avoids a per-event fsync.
            records = bytearray(due * event_record.size)
            lines = []
            successes = 0
            for i in range(due):
                wall_ns, mono_ns = time.time_ns(), time.monotonic_ns()
                line = make(seq + i, wall_ns, rnd)
                if fh is not None:
                    lines.append(line + "\n")
                    ok = True
                else:
                    try:
                        sock.sendto(line.encode(), dest)
                        ok = True
                    except OSError:
                        ok = False
                event_record.pack_into(records, i * event_record.size,
                                       seq + i, wall_ns, mono_ns, int(ok))
                successes += ok
            if fh is not None:
                fh.write("".join(lines))
                fh.flush()
            events_fh.write(records)
            send_errors += due - successes
            seq += due
            sent += due
            sec = int(now - t0)
            per_sec[sec] = per_sec.get(sec, 0) + due
        elif due > 0:
            tns = time.time_ns()
            if fh is not None:
                fh.write("".join(make(seq + i, tns, rnd) + "\n" for i in range(due)))
                fh.flush()
            else:
                for i in range(due):
                    try:
                        sock.sendto((make(seq + i, tns, rnd)).encode(), dest)
                    except OSError:
                        send_errors += 1
            seq += due
            sent += due
            sec = int(now - t0)
            per_sec[sec] = per_sec.get(sec, 0) + due
        time.sleep(max(0.0, tick - (time.monotonic() - now)))
    elapsed = time.monotonic() - t0
    if fh is not None:
        fh.close()
    if events_fh is not None:
        events_fh.close()

    manifest = {
        "mode": a.mode, "kind": a.kind, "target_rate": a.rate, "duration_s": a.duration,
        "seq_start": a.seq_start, "seq_end": seq, "n_sent": sent - send_errors,
        "send_errors": send_errors, "elapsed_s": elapsed, "achieved_rate": sent / elapsed,
        "start_ns": wall0, "end_ns": time.time_ns(),
    }
    if a.events_out:
        digest = hashlib.sha256()
        with open(a.events_out, "rb") as events_file:
            for chunk in iter(lambda: events_file.read(1 << 20), b""):
                digest.update(chunk)
        manifest.update(n_attempted=sent, event_record_bytes=event_record.size,
                        event_record_format="<qqqB:seq,wall_ns,monotonic_ns,sent_ok",
                        event_records_file=a.events_out.rsplit("/", 1)[-1],
                        event_records_sha256=digest.hexdigest())
    with open(a.out + ".json", "w") as f:
        json.dump(manifest, f, indent=1)
    with open(a.out + ".rate.csv", "w") as f:
        f.write("second,events\n")
        for s in sorted(per_sec):
            f.write(f"{s},{per_sec[s]}\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
