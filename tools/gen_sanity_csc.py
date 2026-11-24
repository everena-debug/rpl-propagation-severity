#!/usr/bin/env python3
"""
gen_sanity_csc.py -- emit a ready-to-run Cooja simulation (.csc) for the RPL
security testbed sanity scenario: 1 root, 10 honest nodes, 1 attacker on a
4x3 grid, UDGM radio. Cooja compiles the three firmwares fresh from source
when the file is opened, so it always reflects the current code.

Usage:
    python3 gen_sanity_csc.py > sanity-rank-decrease.csc
"""
import sys

RANGE_TX = 50.0
RANGE_INT = 100.0

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

# mote type identifier -> (description, source, make target)
TYPES = [
    ("mtyperoot", "root",     "examples/rpl-security/root/root.c",         "root.cooja"),
    ("mtypenode", "node",     "examples/rpl-security/node/node.c",         "node.cooja"),
    ("mtypeatk",  "attacker", "examples/rpl-security/attacker/attacker.c", "attacker.cooja"),
]

# id -> (type_identifier, x, y). Grid spacing 40, range 50: orthogonal
# neighbours connect, diagonals do not, so the network is multi-hop.
# Root at a corner; attacker central (id 6), two hops from the root.
MOTES = [
    (1,  "mtyperoot",   0,   0),
    (2,  "mtypenode",  40,   0),
    (3,  "mtypenode",  80,   0),
    (4,  "mtypenode", 120,   0),
    (5,  "mtypenode",   0,  40),
    (6,  "mtypeatk",   40,  40),
    (7,  "mtypenode",  80,  40),
    (8,  "mtypenode", 120,  40),
    (9,  "mtypenode",   0,  80),
    (10, "mtypenode",  40,  80),
    (11, "mtypenode",  80,  80),
    (12, "mtypenode", 120,  80),
]


def motetype_block(identifier, desc, source, target):
    ifaces = "\n".join("      <moteinterface>%s</moteinterface>" % i for i in IFACES)
    return """    <motetype>
      org.contikios.cooja.contikimote.ContikiMoteType
      <identifier>%s</identifier>
      <description>RPL security %s</description>
      <source>[CONTIKI_DIR]/%s</source>
      <commands>$(MAKE) -j$(CPUS) %s TARGET=cooja</commands>
%s
    </motetype>""" % (identifier, desc, source, target, ifaces)


def mote_block(mote_id, type_id, x, y):
    return """    <mote>
      <interface_config>
        org.contikios.cooja.interfaces.Position
        <x>%s</x>
        <y>%s</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        org.contikios.cooja.contikimote.interfaces.ContikiMoteID
        <id>%d</id>
      </interface_config>
      <interface_config>
        org.contikios.cooja.contikimote.interfaces.ContikiRadio
        <bitrate>250.0</bitrate>
      </interface_config>
      <motetype_identifier>%s</motetype_identifier>
    </mote>""" % (float(x), float(y), mote_id, type_id)


def main():
    parts = []
    parts.append('<?xml version="1.0" encoding="UTF-8"?>')
    parts.append("<simconf>")
    parts.append("  <simulation>")
    parts.append("    <title>RPL security sanity (rank decrease)</title>")
    parts.append("    <randomseed>123456</randomseed>")
    parts.append("    <motedelay_us>1000000</motedelay_us>")
    parts.append("    <radiomedium>")
    parts.append("      org.contikios.cooja.radiomediums.UDGM")
    parts.append("      <transmitting_range>%s</transmitting_range>" % RANGE_TX)
    parts.append("      <interference_range>%s</interference_range>" % RANGE_INT)
    parts.append("      <success_ratio_tx>1.0</success_ratio_tx>")
    parts.append("      <success_ratio_rx>1.0</success_ratio_rx>")
    parts.append("    </radiomedium>")
    parts.append("    <events>")
    parts.append("      <logoutput>40000</logoutput>")
    parts.append("    </events>")
    for ident, desc, src, tgt in TYPES:
        parts.append(motetype_block(ident, desc, src, tgt))
    for mote_id, type_id, x, y in MOTES:
        parts.append(mote_block(mote_id, type_id, x, y))
    parts.append("  </simulation>")
    # Plugins: sim control, visualizer, and mote output (filtered to the
    # instrumentation lines so the CSMA noise is hidden by default).
    parts.append("""  <plugin>
    org.contikios.cooja.plugins.SimControl
    <width>280</width><z>2</z><height>160</height><location_x>10</location_x><location_y>10</location_y>
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.Visualizer
    <plugin_config>
      <moterelations>true</moterelations>
      <skin>org.contikios.cooja.plugins.skins.IDVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.UDGMVisualizerSkin</skin>
      <viewport>2.0 0.0 0.0 2.0 40.0 40.0</viewport>
    </plugin_config>
    <width>400</width><z>1</z><height>400</height><location_x>10</location_x><location_y>180</location_y>
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.LogListener
    <plugin_config>
      <filter>ABOOT|ATTACK|PSW|RANK|STAT</filter>
      <formatted_time />
      <coloring />
    </plugin_config>
    <width>900</width><z>0</z><height>600</height><location_x>420</location_x><location_y>10</location_y>
  </plugin>""")
    parts.append("</simconf>")
    sys.stdout.write("\n".join(parts) + "\n")


if __name__ == "__main__":
    main()
