#!/usr/bin/env python3
"""
build_csc.py -- build a headless Cooja scenario (.csc) from parameters:
network size, attacker placement, attack, link loss, and seed. Nodes are laid
out on a grid with the root at a corner; grid spacing and radio range give a
multi-hop network. One node is the attacker, chosen by placement (near the
root, middle, or leaf), the rest are honest nodes.

Usage:
    python3 tools/build_csc.py --nodes 50 --attack rank_decrease \
        --placement middle --loss 0 --seed 0 --out matrix_x.csc
    python3 tools/build_csc.py --nodes 50 --attack baseline --out base.csc

Prints the attacker mote id (or 0 for baseline) on stdout.
"""
import argparse
import math

RANGE_TX = 50.0
RANGE_INT = 100.0
SPACING = 40           # orthogonal neighbours connect (40<50), diagonals do not

IFACES = [
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

ATTACKS = {
    "baseline":      None,
    "rank_decrease": ("RANK_DECREASE", ""),
    "rank_increase": ("RANK_INCREASE", ""),
    "version":       ("VERSION", ""),
    "blackhole":     ("BLACKHOLE", ""),
    "selective_fwd": ("SELECTIVE_FWD", "DROP_PCT=50"),
    "sinkhole":      ("SINKHOLE", ""),
    "dis_flood":     ("DIS_FLOOD", ""),
}
LOSS_RATIO = {0: "1.0", 10: "0.9", 20: "0.8"}


def grid_positions(n):
    """Return [(id, col, row, x, y), ...] with the root (id 1) at (0,0)."""
    cols = int(round(math.sqrt(n)))
    pos = []
    for i in range(n):
        col, row = i % cols, i // cols
        pos.append((i + 1, col, row, col * SPACING, row * SPACING))
    return pos


def pick_attacker(pos, placement):
    """Choose the attacker id by hop distance (grid Manhattan) from the root."""
    if isinstance(placement, str) and placement.startswith("pos"):
        return int(placement[3:])
    root = pos[0]
    dist = {p[0]: abs(p[1] - root[1]) + abs(p[2] - root[2]) for p in pos[1:]}
    dmax = max(dist.values())
    if placement == "near":
        target = max(1, round(0.25 * dmax))
    elif placement == "leaf":
        target = dmax
    else:  # middle
        target = round(0.5 * dmax)
    # closest node to the target hop distance, preferring lower id for stability
    return min(dist, key=lambda i: (abs(dist[i] - target), i))


def motetype_block(ident, desc, src, target, attack):
    ifaces = "\n".join("      <moteinterface>%s</moteinterface>" % i for i in IFACES)
    cmd = "$(MAKE) -j$(CPUS) %s TARGET=cooja" % target
    if attack:
        name, extra = attack
        cmd = ("$(MAKE) -j$(CPUS) %s TARGET=cooja ATTACK=%s %s"
               % (target, name, extra)).strip()
    return ("    <motetype>\n"
            "      org.contikios.cooja.contikimote.ContikiMoteType\n"
            "      <identifier>%s</identifier>\n"
            "      <description>RPL security %s</description>\n"
            "      <source>[CONTIKI_DIR]/examples/rpl-security/%s</source>\n"
            "      <commands>%s</commands>\n"
            "%s\n"
            "    </motetype>" % (ident, desc, src, cmd, ifaces))


def mote_block(mote_id, type_id, x, y):
    return ("    <mote>\n"
            "      <interface_config>\n"
            "        org.contikios.cooja.interfaces.Position\n"
            "        <x>%s</x>\n        <y>%s</y>\n        <z>0.0</z>\n"
            "      </interface_config>\n"
            "      <interface_config>\n"
            "        org.contikios.cooja.contikimote.interfaces.ContikiMoteID\n"
            "        <id>%d</id>\n"
            "      </interface_config>\n"
            "      <interface_config>\n"
            "        org.contikios.cooja.contikimote.interfaces.ContikiRadio\n"
            "        <bitrate>250.0</bitrate>\n"
            "      </interface_config>\n"
            "      <motetype_identifier>%s</motetype_identifier>\n"
            "    </mote>" % (float(x), float(y), mote_id, type_id))


def build(nodes, attack, placement, loss, seed, sim_ms, title):
    pos = grid_positions(nodes)
    _mi = __import__("re").match(r"selective_fwd(\d+)$", attack)
    if _mi:
        aspec = ("SELECTIVE_FWD", "DROP_PCT=%s" % _mi.group(1))
    else:
        aspec = ATTACKS[attack]
    atk_id = 0 if aspec is None else pick_attacker(pos, placement)

    types = [motetype_block("mtyperoot", "root", "root/root.c", "root.cooja", None),
             motetype_block("mtypenode", "node", "node/node.c", "node.cooja", None)]
    if aspec is not None:
        types.append(motetype_block("mtypeatk", "attacker",
                                    "attacker/attacker.c", "attacker.cooja", aspec))

    motes = []
    for (mid, col, row, x, y) in pos:
        if mid == 1:
            tid = "mtyperoot"
        elif mid == atk_id:
            tid = "mtypeatk"
        else:
            tid = "mtypenode"
        motes.append(mote_block(mid, tid, x, y))

    parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<simconf>", "  <simulation>",
             "    <title>%s</title>" % title,
             "    <randomseed>%d</randomseed>" % (100000 + 7919 * seed),
             "    <motedelay_us>1000000</motedelay_us>",
             "    <radiomedium>",
             "      org.contikios.cooja.radiomediums.UDGM",
             "      <transmitting_range>%s</transmitting_range>" % RANGE_TX,
             "      <interference_range>%s</interference_range>" % RANGE_INT,
             "      <success_ratio_tx>1.0</success_ratio_tx>",
             "      <success_ratio_rx>%s</success_ratio_rx>" % LOSS_RATIO[loss],
             "    </radiomedium>",
             "    <events>\n      <logoutput>40000</logoutput>\n    </events>"]
    parts += types + motes
    parts.append("  </simulation>")
    parts.append(
        "  <plugin>\n    org.contikios.cooja.plugins.ScriptRunner\n"
        "    <plugin_config>\n"
        "      <script>TIMEOUT(%d, log.testOK());\n"
        "while(true){\n  log.log(time + \" ID:\" + id + \" \" + msg + \"\\n\");\n"
        "  YIELD();\n}</script>\n"
        "      <active>true</active>\n    </plugin_config>\n  </plugin>" % sim_ms)
    parts.append("</simconf>")
    return "\n".join(parts) + "\n", atk_id


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, default=50)
    ap.add_argument("--attack", default="rank_decrease", choices=list(ATTACKS))
    ap.add_argument("--placement", default="middle", choices=["near", "middle", "leaf"])
    ap.add_argument("--loss", type=int, default=0, choices=[0, 10, 20])
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--sim-ms", type=int, default=1200000)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    title = "%s n%d %s loss%d seed%d" % (a.attack, a.nodes, a.placement, a.loss, a.seed)
    xml, atk = build(a.nodes, a.attack, a.placement, a.loss, a.seed, a.sim_ms, title)
    if a.out:
        open(a.out, "w").write(xml)
    else:
        sys.stdout.write(xml)
    sys.stderr.write("attacker_id=%d nodes=%d placement=%s\n"
                     % (atk, a.nodes, a.placement))
    print(atk)


if __name__ == "__main__":
    import sys
    main()
