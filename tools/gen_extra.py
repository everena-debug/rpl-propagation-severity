#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import build_csc as B
SEEDS = int(os.environ.get("SEEDS", "15"))
SIM_MS = int(os.environ.get("SIM_MS", "1200000"))
POSITIONS = [2, 3, 5, 7, 9, 12, 15, 18, 22, 26, 30, 35, 40, 45, 49]
DROPS = [25, 50, 75]
def main():
    rows = ["scenario,attack,nodes,placement,loss,seed,attacker_id"]
    n = 0
    for attack in ("sinkhole", "rank_decrease"):
        for aid in POSITIONS:
            place = "pos%d" % aid
            for seed in range(SEEDS):
                name = "m_%s_n50_%s_loss0_seed%d" % (attack, place, seed)
                xml, atk = B.build(50, attack, place, 0, seed, SIM_MS, name)
                open(name + ".csc", "w").write(xml)
                rows.append("%s,%s,50,%s,0,%d,%d" % (name, attack, place, seed, atk))
                n += 1
    for d in DROPS:
        atk_attack = "selective_fwd%d" % d
        for seed in range(SEEDS):
            name = "m_selective_fwd_n50_drop%d_loss0_seed%d" % (d, seed)
            xml, atk = B.build(50, atk_attack, "middle", 0, seed, SIM_MS, name)
            open(name + ".csc", "w").write(xml)
            rows.append("%s,%s,50,drop%d,0,%d,%d" % (name, atk_attack, d, seed, atk))
            n += 1
    open("scenarios_extra.csv", "w").write("\n".join(rows) + "\n")
    print("wrote %d new scenarios and scenarios_extra.csv" % n)
if __name__ == "__main__":
    main()
