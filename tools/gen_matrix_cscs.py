#!/usr/bin/env python3
"""
gen_matrix_cscs.py -- generate the Objective 1 scenario matrix as headless
Cooja simulation files. Each scenario keeps the 12-mote sanity topology and
varies one factor at a time: the attack behaviour, the link quality, and the
random seed (for statistics). Every file carries a ScriptRunner timeout script
so it runs headless and exits.

Factors:
  attack : baseline, rank_decrease, rank_increase, version, blackhole,
           selective_fwd
  loss   : rx success ratio 1.0 (0%), 0.9 (10%), 0.8 (20%)
  seed   : SEEDS random seeds (default 10) for confidence intervals

Output: matrix_<attack>_loss<pct>_seed<n>.csc

Usage (from examples/rpl-security):
    python3 tools/gen_matrix_cscs.py            # 10 seeds
    SEEDS=5 python3 tools/gen_matrix_cscs.py    # 5 seeds
"""
import os
import re

BASE = "sanity-rank-decrease.csc"
SIM_MS = 1200000            # 20 minutes of simulated time per run
NSEEDS = int(os.environ.get("SEEDS", "10"))
SEEDS = [100000 + 7919 * i for i in range(NSEEDS)]   # distinct, reproducible

ATTACKS = {
    "baseline":       None,
    "rank_decrease":  ("RANK_DECREASE", ""),
    "rank_increase":  ("RANK_INCREASE", ""),
    "version":        ("VERSION", ""),
    "blackhole":      ("BLACKHOLE", ""),
    "selective_fwd":  ("SELECTIVE_FWD", "DROP_PCT=50"),
    "sinkhole":       ("SINKHOLE", ""),
    "dis_flood":      ("DIS_FLOOD", ""),
}
LOSS = {"0": "1.0", "10": "0.9", "20": "0.8"}

SCRIPT = (
    "  <plugin>\n"
    "    org.contikios.cooja.plugins.ScriptRunner\n"
    "    <plugin_config>\n"
    "      <script>TIMEOUT(%d, log.testOK());\n"
    "while(true){\n"
    "  log.log(time + \" ID:\" + id + \" \" + msg + \"\\n\");\n"
    "  YIELD();\n"
    "}</script>\n"
    "      <active>true</active>\n"
    "    </plugin_config>\n"
    "  </plugin>\n"
    "</simconf>"
) % SIM_MS


def set_attack(s, attack):
    if attack is None:
        s = re.sub(r"    <motetype>\n[^<]*ContikiMoteType\n"
                   r"      <identifier>mtypeatk</identifier>.*?</motetype>\n",
                   "", s, flags=re.S)
        s = s.replace("<motetype_identifier>mtypeatk</motetype_identifier>",
                      "<motetype_identifier>mtypenode</motetype_identifier>")
        return s
    name, extra = attack
    cmd = ("$(MAKE) -j$(CPUS) attacker.cooja TARGET=cooja ATTACK=%s %s"
           % (name, extra)).strip()
    return re.sub(r"(<identifier>mtypeatk</identifier>.*?<commands>)[^<]*(</commands>)",
                  lambda m: m.group(1) + cmd + m.group(2), s, flags=re.S)


def set_loss(s, ratio):
    return re.sub(r"<success_ratio_rx>[^<]*</success_ratio_rx>",
                  "<success_ratio_rx>%s</success_ratio_rx>" % ratio, s)


def set_seed(s, seed):
    return re.sub(r"<randomseed>[^<]*</randomseed>",
                  "<randomseed>%d</randomseed>" % seed, s)


def main():
    base = open(BASE).read().replace("</simconf>", SCRIPT)
    n = 0
    for aname, attack in ATTACKS.items():
        for lpct, ratio in LOSS.items():
            for si, seed in enumerate(SEEDS):
                s = set_attack(base, attack)
                s = set_loss(s, ratio)
                s = set_seed(s, seed)
                s = re.sub(r"<title>[^<]*</title>",
                           "<title>matrix %s loss%s seed%d</title>"
                           % (aname, lpct, si), s, 1)
                open("matrix_%s_loss%s_seed%d.csc" % (aname, lpct, si),
                     "w").write(s)
                n += 1
    print("wrote %d scenarios: %d attacks x %d loss x %d seeds"
          % (n, len(ATTACKS), len(LOSS), len(SEEDS)))
    print("attacker onset is fixed at 2 min in attacker.c")


if __name__ == "__main__":
    main()
