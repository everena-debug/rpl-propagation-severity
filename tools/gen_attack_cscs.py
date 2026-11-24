#!/usr/bin/env python3
"""
gen_attack_cscs.py -- from the sanity scenario, emit one ready-to-run Cooja
simulation per attack type. Each keeps the identical 12-mote topology and only
changes the attacker's compile command so Cooja builds the chosen behaviour.

A `make clean` is prepended to the attacker compile command because the build
caches object files and would otherwise reuse a previously built attack when
only the ATTACK flag changes.

Usage (run from examples/rpl-security):
    python3 tools/gen_attack_cscs.py
"""
import re

BASE = "sanity-rank-decrease.csc"

# filename stem -> (title, ATTACK value, extra make vars)
ATTACKS = {
    "attack_rank_decrease":  ("rank decrease (sinkhole core)", "RANK_DECREASE", ""),
    "attack_rank_increase":  ("rank increase",                 "RANK_INCREASE", ""),
    "attack_version":        ("DODAG version number",          "VERSION",       ""),
    "attack_blackhole":      ("blackhole (drop all forwarded)","BLACKHOLE",     ""),
    "attack_selective_fwd":  ("selective forwarding 50%",       "SELECTIVE_FWD", "DROP_PCT=50"),
}

CLEAN = "$(MAKE) clean TARGET=cooja; "


def main():
    src = open(BASE).read()
    for stem, (title, attack, extra) in ATTACKS.items():
        s = src
        cmd = ("%s$(MAKE) -j$(CPUS) attacker.cooja TARGET=cooja ATTACK=%s %s"
               % (CLEAN, attack, extra)).strip()
        # Replace the attacker motetype's compile command with the attack-specific one.
        s = re.sub(
            r"(<identifier>mtypeatk</identifier>.*?<commands>)[^<]*(</commands>)",
            lambda m: m.group(1) + cmd + m.group(2),
            s, flags=re.S)
        s = s.replace("<title>RPL security sanity (rank decrease)</title>",
                      "<title>RPL security attack - %s</title>" % title)
        open(stem + ".csc", "w").write(s)
        print("wrote %s.csc  (ATTACK=%s %s)" % (stem, attack, extra))


if __name__ == "__main__":
    main()
