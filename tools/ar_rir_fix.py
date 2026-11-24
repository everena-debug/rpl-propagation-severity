#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, re, sys, glob
from collections import defaultdict
ROOT = 1; MHRI = 256; UNREACH = 65535
FN = re.compile(r'm_([a-z_]+)_n(\d+)_([a-z0-9]+)_loss(\d+)_seed(\d+)(_off)?_log')
INSTR = re.compile(r'\]\s+([A-Z]+),(.*)$')
def parse(path):
    atk = onset = None
    stat = defaultdict(list)
    for line in open(path, 'r', errors='ignore'):
        if 'ABOOT' in line:
            m = re.search(r'ABOOT,node=(\d+),sec_attack=\d+,type=\d+,onset_ticks=(\d+)', line)
            if m: atk, onset = int(m.group(1)), int(m.group(2))
            continue
        m = INSTR.search(line)
        if not m or m.group(1) != 'STAT': continue
        f = m.group(2).split(',')
        if len(f) < 4: continue
        try: ts, node, rank, par = int(f[0]), int(f[1]), int(f[2]), int(f[3])
        except ValueError: continue
        stat[node].append((ts, rank, par))
    return atk, (onset if onset is not None else 120000), stat
def captured(parent, atk):
    cap = set()
    for n in parent:
        if n in (ROOT, atk): continue
        seen, cur = set(), n
        while cur is not None and cur != ROOT and cur not in seen:
            seen.add(cur)
            if cur == atk: cap.add(n); break
            cur = parent.get(cur)
    return cap
def metrics(path, N):
    atk, onset, stat = parse(path)
    elig = [n for n in (set(stat) | {ROOT}) if n not in (ROOT, atk)]
    Nel = len(elig) or 1
    times = sorted({ts for s in stat.values() for ts, _, _ in s})
    peak = 0.0; end = set(); endpm = {}
    for t in times:
        if t < onset: continue
        pm = {}
        for node, s in stat.items():
            last = None
            for ts, rk, pr in s:
                if ts <= t: last = (rk, pr)
                else: break
            if last and last[0] != UNREACH and last[1] not in (0, None):
                pm[node] = last[1]
        cap = captured(pm, atk)
        if len(cap) / Nel > peak: peak = len(cap) / Nel
        end, endpm = cap, pm
    depth = 0
    for n in end:
        d, cur, seen = 0, n, set()
        while cur is not None and cur != atk and cur not in seen:
            seen.add(cur); cur = endpm.get(cur); d += 1
        depth = max(depth, d)
    rir = 0
    for n in elig:
        post = [rk for ts, rk, _ in stat.get(n, []) if ts >= onset and rk != UNREACH]
        if post and (max(post) - min(post) > MHRI or abs(post[-1] - post[0]) > MHRI):
            rir += 1
    ddr = 0
    for n in elig:
        s = stat.get(n, [])
        if not s: ddr += 1; continue
        if s[-1][1] == UNREACH: ddr += 1; continue
        pars = [pr for ts, rk, pr in s if ts >= onset]
        sw = sum(1 for i in range(1, len(pars)) if pars[i] != pars[i-1])
        if sw >= 3: ddr += 1
    return peak * 100, 100.0 * rir / Nel, 100.0 * ddr / Nel, len(end) * 100.0 / Nel, depth
def main():
    d = sys.argv[1] if len(sys.argv) > 1 else 'results'
    print('scenario,AR,RIR,DDR,capture,depth')
    for p in sorted(glob.glob(os.path.join(d, 'm_*_log.txt'))):
        m = FN.search(os.path.basename(p))
        if not m: continue
        N = int(m.group(2))
        try:
            ar, rir, ddr, cap, dep = metrics(p, N)
            print('%s,%.2f,%.2f,%.2f,%.2f,%d' % (m.group(0).replace('_log',''), ar, rir, ddr, cap, dep))
        except Exception as e:
            sys.stderr.write('skip %s: %s\n' % (p, e))
if __name__ == '__main__':
    main()
