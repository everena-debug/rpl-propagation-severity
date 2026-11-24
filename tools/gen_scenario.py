#!/usr/bin/env python3
"""
gen_scenario.py -- Cooja .csc generator for the RPL security testbed.

Produces a ready-to-run simulation file with one root, a set of honest nodes,
and a chosen number of attacker nodes, for a given network size, topology,
attacker placement, radio model and random seed. The same file runs in the
Cooja GUI and headless (a ScriptRunner hook ends the run at a fixed sim time
and marks the log complete).

Example:
  python3 gen_scenario.py --nodes 50 --attackers 1 --attack RANK_DECREASE \\
      --placement random --attacker-pos middle --seed 1 --duration 2400 \\
      --out ../scenarios/n50_rankdec_s1.csc

Sizes, attacker ratio, placement, mobility and link loss are all driven from
the command line so a sweep script can emit the whole experiment matrix.
"""
import argparse
import math
import random
import os

CONTIKI_DIR = "[CONTIKI_DIR]"
BASE = CONTIKI_DIR + "/examples/rpl-security"

MOTE_INTERFACES = [
    "org.contikios.cooja.interfaces.Position",
    "org.contikios.cooja.interfaces.Battery",
    "org.contikios.cooja.contikimote.interfaces.ContikiVib",
    "org.contikios.cooja.contikimote.interfaces.ContikiMoteID",
    "org.contikios.cooja.contikimote.interfaces.ContikiRS232",
    "org.contikios.cooja.contikimote.interfaces.ContikiBeeper",
    "org.contikios.cooja.interfaces.RimeAddress",
    "org.contikios.cooja.contikimote.interfaces.ContikiIPAddress",
    "org.contikios.cooja.contikimote.interfaces.ContikiRadio",
    "org.contikios.cooja.contikimote.interfaces.ContikiButton",
    "org.contikios.cooja.contikimote.interfaces.ContikiPIR",
    "org.contikios.cooja.contikimote.interfaces.ContikiClock",
    "org.contikios.cooja.contikimote.interfaces.ContikiLED",
    "org.contikios.cooja.contikimote.interfaces.ContikiCFS",
    "org.contikios.cooja.contikimote.interfaces.ContikiEEPROM",
    "org.contikios.cooja.interfaces.Mote2MoteRelations",
    "org.contikios.cooja.interfaces.MoteAttributes",
]


def motetype(identifier, description, source, command):
    ifaces = "\n".join("      <moteinterface>%s</moteinterface>" % i
                       for i in MOTE_INTERFACES)
    return """    <motetype>
      org.contikios.cooja.contikimote.ContikiMoteType
      <identifier>{id}</identifier>
      <description>{desc}</description>
      <source>{src}</source>
      <commands>{cmd}</commands>
{ifaces}
    </motetype>""".format(id=identifier, desc=description, src=source,
                          cmd=command, ifaces=ifaces)


def mote(x, y, node_id, type_id):
    return """    <mote>
      <interface_config>
        org.contikios.cooja.interfaces.Position
        <x>{x}</x>
        <y>{y}</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        org.contikios.cooja.contikimote.interfaces.ContikiMoteID
        <id>{nid}</id>
      </interface_config>
      <interface_config>
        org.contikios.cooja.contikimote.interfaces.ContikiRadio
        <bitrate>250.0</bitrate>
      </interface_config>
      <motetype_identifier>{tid}</motetype_identifier>
    </mote>""".format(x=x, y=y, nid=node_id, tid=type_id)


def positions(n, placement, area, rng):
    """Return n positions. Node 0 is the root, placed at the area centre."""
    cx, cy = area / 2.0, area / 2.0
    pts = [(cx, cy)]
    if placement == "grid":
        side = int(math.ceil(math.sqrt(n)))
        step = area / max(1, side)
        k = 1
        for r in range(side):
            for c in range(side):
                if k >= n:
                    break
                jx = rng.uniform(-step * 0.15, step * 0.15)
                jy = rng.uniform(-step * 0.15, step * 0.15)
                pts.append((round(c * step + step / 2 + jx, 2),
                            round(r * step + step / 2 + jy, 2)))
                k += 1
    else:  # random
        while len(pts) < n:
            pts.append((round(rng.uniform(0, area), 2),
                        round(rng.uniform(0, area), 2)))
    return pts[:n]


def pick_attackers(pts, count, policy, rng):
    """Choose attacker indices (never the root at index 0) by distance to root."""
    cx, cy = pts[0]
    order = sorted(range(1, len(pts)),
                   key=lambda i: math.hypot(pts[i][0] - cx, pts[i][1] - cy))
    if policy == "near-root":
        cand = order[:max(count, 1) * 3]
    elif policy == "leaf":
        cand = order[-max(count, 1) * 3:]
    elif policy == "middle":
        m = len(order) // 2
        half = max(count, 1) * 3 // 2
        cand = order[max(0, m - half):m + half + 1]
    else:  # random
        cand = order
    rng.shuffle(cand)
    return set(cand[:count])


def script_runner(duration_s):
    """Headless hook: end the run at duration_s and flag the log complete."""
    js = ("TIMEOUT(%d, log.log('done\\n'));\\n"
          "while(true){ YIELD(); }") % (duration_s * 1000)
    return """  <plugin>
    org.contikios.cooja.plugins.ScriptRunner
    <plugin_config>
      <script>{js}</script>
      <active>true</active>
    </plugin_config>
  </plugin>""".format(js=js)


def build(args):
    rng = random.Random(args.seed)
    n = args.nodes
    pts = positions(n, args.placement, args.area, rng)
    attackers = pick_attackers(pts, args.attackers, args.attacker_pos, rng)

    of_flag = " MAKE_WITH_OF0=1" if args.of == "OF0" else ""
    atk_cmd = ("$(MAKE) -j$(CPUS) attacker.cooja TARGET=cooja "
               "ATTACK=%s RANK_DELTA=%d DROP_PCT=%d%s"
               % (args.attack, args.rank_delta, args.drop_pct, of_flag))

    types = [
        motetype("mtype_root", "Root",
                 BASE + "/root/root.c",
                 "$(MAKE) -j$(CPUS) root.cooja TARGET=cooja" + of_flag),
        motetype("mtype_node", "Honest node",
                 BASE + "/node/node.c",
                 "$(MAKE) -j$(CPUS) node.cooja TARGET=cooja" + of_flag),
    ]
    if attackers:
        types.append(motetype("mtype_attacker", "Attacker",
                              BASE + "/attacker/attacker.c", atk_cmd))

    motes = []
    for i, (x, y) in enumerate(pts):
        nid = i + 1
        if i == 0:
            tid = "mtype_root"
        elif i in attackers:
            tid = "mtype_attacker"
        else:
            tid = "mtype_node"
        motes.append(mote(x, y, nid, tid))

    csc = """<?xml version="1.0" encoding="UTF-8"?>
<simconf>
  <simulation>
    <title>RPL-SEC n{n} {atk} atk{na} {pos} seed{seed}</title>
    <randomseed>{seed}</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>
      org.contikios.cooja.radiomediums.UDGM
      <transmitting_range>{trange}</transmitting_range>
      <interference_range>{irange}</interference_range>
      <success_ratio_tx>{tx}</success_ratio_tx>
      <success_ratio_rx>{rx}</success_ratio_rx>
    </radiomedium>
    <events>
      <logoutput>1000000</logoutput>
    </events>
{types}
{motes}
  </simulation>
{script}
</simconf>
""".format(n=n, atk=(args.attack if attackers else "baseline"),
           na=args.attackers, pos=args.attacker_pos, seed=args.seed,
           trange=args.range, irange=args.range * 2.0,
           tx=args.tx_success, rx=args.rx_success,
           types="\n".join(types), motes="\n".join(motes),
           script=script_runner(args.duration))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        f.write(csc)
    print("wrote %s : %d nodes (1 root, %d attacker(s) at %s, %d honest)"
          % (args.out, n, len(attackers), args.attacker_pos,
             n - 1 - len(attackers)))


def main():
    p = argparse.ArgumentParser(description="Cooja .csc generator (RPL security)")
    p.add_argument("--nodes", type=int, default=50, help="total nodes incl. root")
    p.add_argument("--attackers", type=int, default=1)
    p.add_argument("--attack", default="RANK_DECREASE",
                   choices=["RANK_DECREASE", "RANK_INCREASE", "VERSION",
                            "BLACKHOLE", "SELECTIVE_FWD"])
    p.add_argument("--attacker-pos", default="middle",
                   choices=["near-root", "middle", "leaf", "random"])
    p.add_argument("--placement", default="random", choices=["random", "grid"])
    p.add_argument("--area", type=float, default=200.0, help="square side, m")
    p.add_argument("--range", type=float, default=50.0, help="UDGM tx range, m")
    p.add_argument("--tx-success", type=float, default=1.0)
    p.add_argument("--rx-success", type=float, default=1.0)
    p.add_argument("--rank-delta", type=int, default=256)
    p.add_argument("--drop-pct", type=int, default=50)
    p.add_argument("--of", default="MRHOF", choices=["MRHOF", "OF0"])
    p.add_argument("--duration", type=int, default=2400, help="sim seconds")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--out", default="scenario.csc")
    build(p.parse_args())


if __name__ == "__main__":
    main()
