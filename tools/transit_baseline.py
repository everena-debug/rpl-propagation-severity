#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, re, sys, glob
from collections import defaultdict
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import build_csc as B
ROOT = 1; UNREACH = 65535
FN = re.compile(r'm_baseline_n(\d+)_([a-z]+)_loss(\d+)_seed(\d+)_log')
INSTR = re.compile(r'\]\s+([A-Z]+),(.*)$')
def final_parent(path):
    stat = defaultdict(list)
    for line in open(path, 'r', errors='ignore'):
        m = INSTR.search(line)
        if not m or m.group(1) != 'STAT': continue
        f = m.group(2).split(',')
        if len(f) < 4: continue
        try: ts, node, rank, par = int(f[0]), int(f[1]), int(f[2]), int(f[3])
        except ValueError: continue
        stat[node].append((ts, rank, par))
    pm = {}
    for node, s in stat.items():
        rk, pr = s[-1][1], s[-1][2]
        if rk != UNREACH and pr not in (0, None):
            pm[node] = pr
    return pm, set(stat) | {ROOT}
def transit_through(pm, node):
    cap = set()
    for n in pm:
        if n in (ROOT, node): continue
        seen, cur = set(), n
        while cur is not None and cur != ROOT and cur not in seen:
            seen.add(cur)
            if cur == node: cap.add(n); break
            cur = pm.get(cur)
    return cap
def main():
    d = sys.argv[1] if len(sys.argv) > 1 else 'results'
    print('scenario,would_be_attacker,transit_pct')
    for p in sorted(glob.glob(os.path.join(d, 'm_baseline_*_log.txt'))):
        m = FN.search(os.path.basename(p))
        if not m: continue
        N, place = int(m.group(1)), m.group(2)
        node = B.pick_attacker(B.grid_positions(N), place)
        pm, present = final_parent(p)
        Nel = len([x for x in present if x not in (ROOT, node)]) or 1
        t = 100.0 * len(transit_through(pm, node)) / Nel
        print('%s,%d,%.2f' % (m.group(0).replace('_log', ''), node, t))
if __name__ == '__main__':
    main()
