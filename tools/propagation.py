#!/usr/bin/env python3
"""
propagation.py -- build the temporal attack-propagation view from one trace log
and compute the propagation metrics for Objective 1.

From the STAT samples it reconstructs the preferred-parent tree at each sample
time, tracks the set of nodes whose route to the root passes through the
attacker (the captured set) over time, and derives:

  AR   attack reach          max captured fraction of the network
  T50  time to 50% spread    sample time to reach half of max capture, from onset
  T90  time to 90% spread    likewise for 90%
  depth  propagation depth   max hop distance of a captured node from the attacker
  DDR  DODAG disruption      fraction of nodes disconnected or unstable at the end
  RIR  rank inconsistency    fraction of nodes whose rank changed after onset
  PSR  parent-switch rate    parent switches after onset per minute
  persistence                if the attack stops, time for capture to fall back

Usage:
    python3 tools/propagation.py results/<name>_log.txt --attacker 6
    python3 tools/propagation.py <log> --attacker 6 --csv NAME
"""
import argparse
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze_log import parse

UNREACH = 65535


def parent_at(stat_rows, root):
    """time-sorted list of (t, {node: (parent, rank)}) snapshots from STAT."""
    per_t = defaultdict(dict)
    for f in stat_rows:
        if len(f) < 14:
            continue
        t, node, rank, parent = int(f[1]), int(f[2]), int(f[3]), int(f[4])
        per_t[t][node] = (parent, rank)
    times = sorted(per_t)
    # carry forward last known state so every snapshot is complete
    state, snaps = {}, []
    for t in times:
        state = dict(state)
        state.update(per_t[t])
        snaps.append((t, dict(state)))
    return snaps


def captured(state, atk, root):
    cap = set()
    for n in state:
        if n in (root, atk):
            continue
        seen, cur = set(), n
        while cur not in (0, root) and cur not in seen:
            seen.add(cur)
            p = state.get(cur, (0, 0))[0]
            if p == atk:
                cap.add(n)
                break
            cur = p
    return cap


def subtree_depth(state, atk, root):
    """max hop distance from the attacker among captured nodes."""
    children = defaultdict(list)
    for n, (p, _) in state.items():
        children[p].append(n)
    depth, frontier, d = 0, [atk], 0
    seen = {atk}
    while frontier:
        nxt = []
        for u in frontier:
            for c in children.get(u, []):
                if c not in seen and c != root:
                    seen.add(c); nxt.append(c)
        if nxt:
            d += 1; depth = d
        frontier = nxt
    return depth


def compute(log, atk, root):
    ev, aboot, attack, energest = parse(log)
    onset = None
    stop = None
    for a in attack:
        f = a.split(",")
        if len(f) >= 4 and f[3] == "active=1" and onset is None:
            onset = int(f[1])
        if len(f) >= 4 and f[3] == "active=0":
            stop = int(f[1])
    snaps = parent_at(ev["STAT"], root)
    if not snaps:
        return None
    nodes = set()
    for _, st in snaps:
        nodes |= set(st)
    N = len([n for n in nodes if n not in (root, atk)])

    curve = [(t, len(captured(st, atk, root))) for t, st in snaps]
    post = [(t, c) for t, c in curve if onset is None or t >= onset]
    cmax = max((c for _, c in post), default=0)
    AR = cmax / N if N else 0.0

    def time_to(frac):
        thr = frac * cmax
        for t, c in post:
            if c >= thr and c > 0:
                return t - (onset or 0)
        return None
    T50, T90 = time_to(0.5), time_to(0.9)

    final_state = snaps[-1][1]
    depth = subtree_depth(final_state, atk, root)

    # DODAG disruption: disconnected (unreachable rank) or unstable (many switches)
    last_stat = {}
    for f in ev["STAT"]:
        if len(f) >= 14:
            last_stat[int(f[2])] = f
    disrupted = 0
    for n, f in last_stat.items():
        if n in (root,):
            continue
        rank, psw = int(f[3]), int(f[5])
        if rank == UNREACH or psw >= 4:
            disrupted += 1
    DDR = disrupted / N if N else 0.0

    # rank inconsistency: nodes with a RANK change after onset
    rir_nodes = set()
    for f in ev["RANK"]:
        if len(f) >= 3 and (onset is None or int(f[1]) >= onset):
            rir_nodes.add(int(f[2]))
    RIR = len([n for n in rir_nodes if n not in (root, atk)]) / N if N else 0.0

    # parent-switch rate after onset (per minute)
    psw_after = [f for f in ev["PSW"] if len(f) >= 5 and (onset is None or int(f[1]) >= onset)]
    dur_min = max(1e-9, (snaps[-1][0] - (onset or 0)) / 60000.0)
    PSR = len(psw_after) / dur_min

    # persistence: if attack stopped, time for capture to fall to <=25% of max
    persistence = None
    if stop is not None and cmax > 0:
        for t, c in curve:
            if t >= stop and c <= 0.25 * cmax:
                persistence = t - stop
                break

    return dict(onset=onset, stop=stop, N=N, cmax=cmax, AR=AR, T50=T50, T90=T90,
                depth=depth, DDR=DDR, RIR=RIR, PSR=PSR, persistence=persistence,
                curve=post)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--attacker", type=int, default=6)
    ap.add_argument("--root", type=int, default=1)
    ap.add_argument("--csv", metavar="NAME", default=None)
    a = ap.parse_args()
    M = compute(a.log, a.attacker, a.root)
    if M is None:
        print("no STAT data in", a.log); return

    def ms(x):
        return "n/a" if x is None else "%.0f" % (x / 1000.0) + "s"

    if a.csv is not None:
        print("%s,%.3f,%s,%s,%d,%.3f,%.3f,%.2f,%s" % (
            a.csv, M["AR"],
            "" if M["T50"] is None else "%.0f" % (M["T50"] / 1000.0),
            "" if M["T90"] is None else "%.0f" % (M["T90"] / 1000.0),
            M["depth"], M["DDR"], M["RIR"], M["PSR"],
            "" if M["persistence"] is None else "%.0f" % (M["persistence"] / 1000.0)))
        return

    print("Temporal propagation metrics for", a.log)
    print("  attacker=%d root=%d onset=%s stop=%s N=%d"
          % (a.attacker, a.root, M["onset"], M["stop"], M["N"]))
    print("  AR  attack reach            %.1f%% (%d of %d nodes)"
          % (100 * M["AR"], M["cmax"], M["N"]))
    print("  T50 time to 50%% spread      %s (from onset)" % ms(M["T50"]))
    print("  T90 time to 90%% spread      %s (from onset)" % ms(M["T90"]))
    print("  depth propagation depth     %d hops from attacker" % M["depth"])
    print("  DDR DODAG disruption ratio  %.1f%%" % (100 * M["DDR"]))
    print("  RIR rank inconsistency      %.1f%%" % (100 * M["RIR"]))
    print("  PSR parent-switch rate      %.2f per minute" % M["PSR"])
    print("  persistence after stop      %s" % ms(M["persistence"]))
    print("  capture curve (t_s, captured):",
          [(round(t / 1000), c) for t, c in M["curve"][::max(1, len(M["curve"]) // 8)]])


if __name__ == "__main__":
    main()
