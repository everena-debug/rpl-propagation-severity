#!/usr/bin/env python3
"""
aggregate2.py -- join the per-run summary with the scenario manifest and
produce the factor-wise Objective 1 results: the attack comparison at the
reference configuration (with significance), and the size, placement, and
link-loss sweeps.

Usage:
    python3 tools/aggregate2.py results/summary.csv scenarios_manifest.csv
"""
import csv
import math
import sys
from collections import defaultdict

# ---- inlined statistics (kept self-contained, no external imports) ----
_T = {1: 12.71, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
      8: 2.306, 9: 2.262, 10: 2.228, 12: 2.179, 15: 2.131, 20: 2.086,
      25: 2.060, 30: 2.042}


def _tcrit(df):
    if df <= 0:
        return 0.0
    if df in _T:
        return _T[df]
    for k in sorted(_T):
        if df <= k:
            return _T[k]
    return 1.96


def mean_ci(xs):
    n = len(xs)
    if n == 0:
        return 0.0, 0.0, 0
    mu = sum(xs) / n
    if n == 1:
        return mu, 0.0, 1
    sd = math.sqrt(sum((x - mu) ** 2 for x in xs) / (n - 1))
    return mu, _tcrit(n - 1) * sd / math.sqrt(n), n


def _chisq_sf(x, k):
    if x <= 0 or k <= 0:
        return 1.0
    t = (x / k) ** (1.0 / 3.0)
    z = (t - (1 - 2.0 / (9 * k))) / math.sqrt(2.0 / (9 * k))
    return 0.5 * math.erfc(z / math.sqrt(2))


def _rank(vals):
    order = sorted(range(len(vals)), key=lambda i: vals[i])
    ranks = [0.0] * len(vals)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and vals[order[j + 1]] == vals[order[i]]:
            j += 1
        r = (i + j) / 2.0 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = r
        i = j + 1
    return ranks


def kruskal(groups):
    flat, gid = [], []
    for gi, g in enumerate(groups):
        flat += g; gid += [gi] * len(g)
    if not flat:
        return 0.0, len(groups) - 1, 1.0
    ranks = _rank(flat)
    rs = defaultdict(float); ng = defaultdict(int)
    for g, r in zip(gid, ranks):
        rs[g] += r; ng[g] += 1
    N = len(flat)
    H = 12.0 / (N * (N + 1)) * sum(rs[g] ** 2 / ng[g] for g in rs) - 3 * (N + 1)
    df = len(groups) - 1
    return H, df, _chisq_sf(H, df)


def mannwhitney_p(a, b):
    flat = a + b
    ranks = _rank(flat)
    Ra = sum(ranks[:len(a)])
    na, nb = len(a), len(b)
    U = Ra - na * (na + 1) / 2.0
    mu = na * nb / 2.0
    sigma = math.sqrt(na * nb * (na + nb + 1) / 12.0)
    if sigma == 0:
        return 1.0
    return math.erfc(abs((U - mu) / sigma) / math.sqrt(2))


METRICS = ["capture_pct", "pdr_pct", "rtt_mean_ms", "lat_mean_ms",
           "atk_dio_tx", "total_ctrl"]
REF = dict(nodes="50", placement="middle", loss="0")
ATK_ORDER = ["baseline", "rank_decrease", "rank_increase", "version",
             "blackhole", "selective_fwd", "sinkhole", "dis_flood"]


def load(summary, manifest):
    man = {r["scenario"]: r for r in csv.DictReader(open(manifest))}
    rows = []
    for r in csv.DictReader(open(summary)):
        m = man.get(r["scenario"])
        if not m:
            continue
        row = dict(attack=m["attack"], nodes=m["nodes"],
                   placement=m["placement"], loss=m["loss"], seed=m["seed"])
        for k in METRICS:
            row[k] = float(r[k])
        rows.append(row)
    return rows


def group(rows, keyfn):
    g = defaultdict(lambda: defaultdict(list))
    for r in rows:
        for m in METRICS:
            g[keyfn(r)][m].append(r[m])
    return g


def table(title, g, keys, cols=("capture_pct", "pdr_pct", "total_ctrl",
                                "atk_dio_tx", "rtt_mean_ms")):
    print("\n== %s ==" % title)
    print("%-16s %13s %13s %14s %12s %11s"
          % ("group", "capture%", "PDR%", "control", "atkDIO", "RTTms"))
    for k in keys:
        if k not in g:
            continue
        cells = []
        for m in cols:
            mu, ci, _ = mean_ci(g[k][m])
            cells.append("%6.1f+-%-4.1f" % (mu, ci))
        print("%-16s %s" % (k, " ".join(cells)))


def main():
    summary = sys.argv[1] if len(sys.argv) > 1 else "results/summary.csv"
    manifest = sys.argv[2] if len(sys.argv) > 2 else "scenarios_manifest.csv"
    rows = load(summary, manifest)
    if not rows:
        print("no joined rows"); return
    outdir = summary.rsplit("/", 1)[0] if "/" in summary else "."

    # 1) attack comparison at the reference configuration
    ref = [r for r in rows if r["nodes"] == REF["nodes"]
           and r["placement"] == REF["placement"] and r["loss"] == REF["loss"]]
    g = group(ref, lambda r: r["attack"])
    order = [a for a in ATK_ORDER if a in g]
    table("Attack comparison at reference (n=%s, %s, loss %s)"
          % (REF["nodes"], REF["placement"], REF["loss"]), g, order)

    if "baseline" in g:
        print("\n  significance vs baseline (Kruskal-Wallis; MW Holm-adj):")
        for m in ["capture_pct", "pdr_pct", "total_ctrl"]:
            H, df, p = kruskal([g[a][m] for a in order])
            print("    %-12s H=%.2f df=%d p=%.3g" % (m, H, df, p))
            others = [a for a in order if a != "baseline"]
            raw = sorted(((a, mannwhitney_p(g["baseline"][m], g[a][m]))
                          for a in others), key=lambda t: t[1])
            for i, (a, pv) in enumerate(raw):
                padj = min(1.0, pv * (len(raw) - i))
                print("        vs %-14s adj=%.3g %s"
                      % (a, padj, "*" if padj < 0.05 else ""))

    # 2) size sweep (key attacks, reference placement and loss)
    ssz = [r for r in rows if r["placement"] == REF["placement"]
           and r["loss"] == REF["loss"]]
    for a in ["rank_decrease", "sinkhole", "version", "dis_flood"]:
        sub = [r for r in ssz if r["attack"] == a]
        if not sub:
            continue
        g = group(sub, lambda r: "n=" + r["nodes"])
        table("Size sweep: %s" % a, g, sorted(g, key=lambda k: int(k[2:])))

    # 3) placement sweep
    for a in ["rank_decrease", "sinkhole"]:
        sub = [r for r in rows if r["attack"] == a
               and r["nodes"] == REF["nodes"] and r["loss"] == REF["loss"]]
        if not sub:
            continue
        g = group(sub, lambda r: r["placement"])
        table("Placement sweep: %s" % a, g, ["near", "middle", "leaf"])

    # 4) loss sweep
    for a in ["sinkhole", "blackhole", "version"]:
        sub = [r for r in rows if r["attack"] == a
               and r["nodes"] == REF["nodes"] and r["placement"] == REF["placement"]]
        if not sub:
            continue
        g = group(sub, lambda r: "loss" + r["loss"])
        table("Link-loss sweep: %s" % a, g,
              sorted(g, key=lambda k: int(k[4:])))

    # write the reference attack table to CSV
    g = group(ref, lambda r: r["attack"])
    with open(outdir + "/agg_reference.csv", "w") as f:
        f.write("attack,n," + ",".join(m + "_mean," + m + "_ci" for m in METRICS) + "\n")
        for a in order:
            n = len(g[a]["pdr_pct"])
            cells = []
            for m in METRICS:
                mu, ci, _ = mean_ci(g[a][m])
                cells += ["%.2f" % mu, "%.2f" % ci]
            f.write("%s,%d,%s\n" % (a, n, ",".join(cells)))
    print("\nwrote %s/agg_reference.csv" % outdir)


if __name__ == "__main__":
    main()
