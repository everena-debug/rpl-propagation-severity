#!/usr/bin/env python3
"""
gen_matrix2.py -- generate the Objective 1 experiment matrix using the topology
builder, varying one factor at a time around a reference configuration, and
write a manifest so the runner knows each scenario's attacker id.

Reference: 50 nodes, attacker in the middle, 0% loss, MRHOF.
Factors varied one at a time (each across SEEDS seeds):
  attack     : all eight (at the reference size, placement, loss)
  size       : 20, 50, 100 nodes  (subset of attacks)
  placement  : near, middle, leaf (subset of attacks)
  link loss  : 0, 10, 20 percent  (subset of attacks)

Output: m_*.csc and scenarios_manifest.csv
(columns: scenario, attack, nodes, placement, loss, seed, attacker_id)

Usage (from examples/rpl-security):
    python3 tools/gen_matrix2.py           # SEEDS default 5
    SEEDS=10 python3 tools/gen_matrix2.py
"""
import os
import build_csc as B

SEEDS = int(os.environ.get("SEEDS", "5"))
SIM_MS = int(os.environ.get("SIM_MS", "1200000"))

REF = dict(nodes=50, placement="middle", loss=0)
ALL_ATTACKS = ["baseline", "rank_decrease", "rank_increase", "version",
               "blackhole", "selective_fwd", "sinkhole", "dis_flood"]
KEY = ["baseline", "rank_decrease", "sinkhole", "version", "dis_flood"]

# one-factor-at-a-time cells: (attack, nodes, placement, loss)
def design():
    cells = set()
    for a in ALL_ATTACKS:                                  # attack sweep
        cells.add((a, REF["nodes"], REF["placement"], REF["loss"]))
    for a in KEY:                                          # size sweep
        for n in (20, 50, 100):
            cells.add((a, n, REF["placement"], REF["loss"]))
    for a in ("rank_decrease", "sinkhole"):                # placement sweep
        for p in ("near", "middle", "leaf"):
            cells.add((a, REF["nodes"], p, REF["loss"]))
    for a in ("baseline", "sinkhole", "blackhole", "version"):  # loss sweep
        for l in (0, 10, 20):
            cells.add((a, REF["nodes"], REF["placement"], l))
    return sorted(cells)


def main():
    rows = ["scenario,attack,nodes,placement,loss,seed,attacker_id"]
    n = 0
    for (attack, nodes, placement, loss) in design():
        for seed in range(SEEDS):
            name = "m_%s_n%d_%s_loss%d_seed%d" % (attack, nodes, placement, loss, seed)
            title = name
            xml, atk = B.build(nodes, attack, placement, loss, seed, SIM_MS, title)
            open(name + ".csc", "w").write(xml)
            rows.append("%s,%s,%d,%s,%d,%d,%d"
                        % (name, attack, nodes, placement, loss, seed, atk))
            n += 1
    open("scenarios_manifest.csv", "w").write("\n".join(rows) + "\n")
    print("wrote %d scenarios and scenarios_manifest.csv (%d cells x %d seeds)"
          % (n, len(design()), SEEDS))


if __name__ == "__main__":
    main()
