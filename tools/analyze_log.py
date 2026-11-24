#!/usr/bin/env python3
"""
analyze_log.py -- parse a Cooja mote-output log from the RPL security testbed
and report the Objective 1 metrics and the attack effect.

Usage:
    python3 analyze_log.py LOG [--attacker 6] [--root 1]
    python3 analyze_log.py LOG --attacker 6 --csv NAME   # one summary row

It reads the machine-parseable trace lines (STAT, PSW, RANK, CTRL, APP, RTT,
ATTACK, ABOOT) and the Energest radio lines, and reports packet delivery ratio,
one-way latency, round-trip time, control overhead, radio duty cycle, and the
sub-DODAG captured by the attacker. With --csv it prints a single comma row
(no header) for aggregation across many runs.
"""
import argparse
import re
import statistics as st
from collections import defaultdict


def parse(path):
    ev = {k: [] for k in ("STAT", "PSW", "RANK", "CTRL", "APP", "RTT")}
    aboot, attack = [], []
    energest = defaultdict(dict)
    cur_node = None
    for line in open(path, errors="ignore"):
        m = re.search(r"ID:(\d+)", line)
        if m:
            cur_node = int(m.group(1))
        for k in ev:
            idx = line.find(k + ",")
            if idx != -1:
                ev[k].append(line[idx:].strip().split(","))
                break
        if "ABOOT," in line:
            aboot.append(line[line.find("ABOOT,"):].strip())
        if "ATTACK," in line:
            attack.append(line[line.find("ATTACK,"):].strip())
        rm = re.search(r"Radio (Tx|Rx|total)\s*:\s*(\d+)/\s*(\d+)", line)
        if rm and cur_node is not None:
            energest[cur_node][rm.group(1)] = (int(rm.group(2)), int(rm.group(3)))
    return ev, aboot, attack, energest


def compute(ev, attack, atk, root):
    """Return a metrics dict from the parsed events."""
    onset = None
    for a in attack:
        f = a.split(",")
        if len(f) >= 4 and f[3] == "active=1":
            onset = int(f[1]); break

    last_parent, last_stat = {}, {}
    for f in ev["STAT"]:
        if len(f) < 14:
            continue
        last_parent[int(f[2])] = int(f[4])
        last_stat[int(f[2])] = f

    def captured(parent_of):
        cap = set()
        for n in parent_of:
            if n in (root, atk):
                continue
            seen, cur = set(), n
            while cur not in (0, root) and cur not in seen:
                seen.add(cur)
                p = parent_of.get(cur, 0)
                if p == atk:
                    cap.add(n); break
                cur = p
        return cap

    cap = captured(last_parent)
    nnodes = len([n for n in last_parent if n not in (root, atk)])

    sent, delivered, tx_t, rx_t = set(), set(), {}, {}
    for f in ev["APP"]:
        if len(f) < 6:
            continue
        t, node, dr, seq, peer = int(f[1]), int(f[2]), f[3], int(f[4]), int(f[5])
        if dr == "TX" and node != root:
            sent.add((node, seq)); tx_t[(node, seq)] = t
        elif dr == "RX" and node == root:
            delivered.add((peer, seq)); rx_t[(peer, seq)] = t
    matched = sent & delivered
    pdr = 100.0 * len(matched) / max(len(sent), 1)
    lat = [rx_t[k] - tx_t[k] for k in matched
           if k in tx_t and k in rx_t and rx_t[k] >= tx_t[k]]
    rtts = [int(f[4]) for f in ev["RTT"] if len(f) >= 5]

    tot_ctrl = 0
    for n, f in last_stat.items():
        tot_ctrl += int(f[6]) + int(f[8]) + int(f[10])
    atk_dio = int(last_stat[atk][6]) if atk in last_stat else 0

    return dict(onset=onset, cap=cap, nnodes=nnodes, last_parent=last_parent,
                last_stat=last_stat, sent=sent, matched=matched, pdr=pdr,
                lat=lat, rtts=rtts, tot_ctrl=tot_ctrl, atk_dio=atk_dio)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--attacker", type=int, default=6)
    ap.add_argument("--root", type=int, default=1)
    ap.add_argument("--csv", metavar="NAME", default=None,
                    help="print one summary row labelled NAME, no report")
    args = ap.parse_args()
    atk, root = args.attacker, args.root

    ev, aboot, attack, energest = parse(args.log)
    M = compute(ev, attack, atk, root)

    def mean(x):
        return st.mean(x) if x else 0.0

    if args.csv is not None:
        print("%s,%d,%d,%.0f,%.1f,%.1f,%.1f,%d,%d" % (
            args.csv, atk, len(M["cap"]),
            100.0 * len(M["cap"]) / max(M["nnodes"], 1),
            M["pdr"], mean(M["rtts"]), mean(M["lat"]),
            M["atk_dio"], M["tot_ctrl"]))
        return

    print("=" * 64)
    print("RPL security testbed - log analysis")
    print("=" * 64)
    for a in aboot:
        print("boot :", a)
    for a in attack:
        print("phase:", a)
    print("attacker:", atk, "| root:", root, "| onset(ms):", M["onset"])

    print("\n-- Attack effect (final state) --")
    print("preferred parent per node:",
          {n: M["last_parent"][n] for n in sorted(M["last_parent"])})
    print("direct children of attacker:",
          sorted(n for n in M["last_parent"] if M["last_parent"][n] == atk))
    print("captured sub-DODAG:", sorted(M["cap"]))
    print("capture ratio: %d/%d = %.0f%%" %
          (len(M["cap"]), M["nnodes"],
           100.0 * len(M["cap"]) / max(M["nnodes"], 1)))

    print("\n-- Packet delivery --")
    print("sent: %d | delivered to root: %d | PDR: %.1f%%"
          % (len(M["sent"]), len(M["matched"]), M["pdr"]))
    if M["lat"]:
        print("\n-- One-way latency (ms) --")
        print("mean %.1f | median %.1f | p95 %.1f | max %d"
              % (mean(M["lat"]), st.median(M["lat"]),
                 sorted(M["lat"])[int(0.95 * len(M["lat"])) - 1], max(M["lat"])))
    if M["rtts"]:
        print("\n-- Round-trip time (ms) --")
        print("samples %d | mean %.1f | median %.1f | p95 %.1f | max %d"
              % (len(M["rtts"]), mean(M["rtts"]), st.median(M["rtts"]),
                 sorted(M["rtts"])[int(0.95 * len(M["rtts"])) - 1], max(M["rtts"])))

    print("\n-- Control overhead (final cumulative counts) --")
    print("node  dio_tx dis_tx dao_tx  pswitch  rank")
    for n in sorted(M["last_stat"]):
        f = M["last_stat"][n]
        tag = " <-- attacker" if n == atk else (" (root)" if n == root else "")
        print("%3d   %6d %6d %6d  %6d  %4d%s"
              % (n, int(f[6]), int(f[8]), int(f[10]), int(f[5]), int(f[3]), tag))
    print("total control messages sent:", M["tot_ctrl"])

    if energest:
        print("\n-- Radio duty cycle (last Energest window) --")
        for n in sorted(energest):
            e = energest[n]
            if "Tx" in e and "Rx" in e and "total" in e:
                busy, total = e["Tx"][0] + e["Rx"][0], e["total"][1]
                print("node %3d: radio on %.1f%% (tx %.2f%%, rx %.2f%%)"
                      % (n, 100.0 * busy / total,
                         100.0 * e["Tx"][0] / total, 100.0 * e["Rx"][0] / total))
        print("note: Cooja motes keep the radio always on; compare energy via Tx share.")


if __name__ == "__main__":
    main()
