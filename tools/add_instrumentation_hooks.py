#!/usr/bin/env python3
"""
add_instrumentation_hooks.py

Insert the RPL security testbed's instrumentation hooks into a Contiki-NG
rpl-icmp6.c that already carries the base rank/version hooks. It adds:

  * five no-op fallback macro definitions (RPL_SEC_ON_DIO_RX / DIS_RX /
    DIO_TX / DIS_TX / DAO_TX), so non-testbed builds still compile; and
  * the five call sites that emit the propagation-graph edges and count
    control traffic (DIO/DIS receive, DIO/DIS/DAO transmit).

The script is safe to run:
  * it refuses to run twice (detects the hooks are already present);
  * it locates every insertion point before writing anything, and aborts
    without touching the file if any anchor is missing; and
  * it writes a .bak copy of the original next to the file.

Usage:
    python3 add_instrumentation_hooks.py /path/to/os/net/routing/rpl-lite/rpl-icmp6.c
"""
import sys
import shutil

MACRO_ANCHOR = (
    "#ifndef RPL_DIO_VERSION_HOOK\n"
    "#define RPL_DIO_VERSION_HOOK(v) (v)\n"
    "#endif\n"
)

MACRO_BLOCK = """
/* Instrumentation hooks (no-op by default). Populated for every image in the
 * security testbed so each node records the control traffic it sends and
 * receives; the *_RX hooks also emit the source id of each received DIO/DIS,
 * which is one edge of the temporal attack-propagation graph. */
#ifndef RPL_SEC_ON_DIO_RX
#define RPL_SEC_ON_DIO_RX(src) do {} while(0)
#endif
#ifndef RPL_SEC_ON_DIS_RX
#define RPL_SEC_ON_DIS_RX(src) do {} while(0)
#endif
#ifndef RPL_SEC_ON_DIO_TX
#define RPL_SEC_ON_DIO_TX() do {} while(0)
#endif
#ifndef RPL_SEC_ON_DIS_TX
#define RPL_SEC_ON_DIS_TX() do {} while(0)
#endif
#ifndef RPL_SEC_ON_DAO_TX
#define RPL_SEC_ON_DAO_TX() do {} while(0)
#endif
"""

# Each call-site: a unique substring identifying the target line, the hook to
# insert, and whether it goes before (True) or after (False) that line.
CALL_SITES = [
    ("rpl_process_dio(&from",            "RPL_SEC_ON_DIO_RX(&from);",                       True),
    ("rpl_process_dis(&UIP_IP_BUF",      "RPL_SEC_ON_DIS_RX(&UIP_IP_BUF->srcipaddr);",      True),
    ("RPL_CODE_DIS, 2)",                 "RPL_SEC_ON_DIS_TX();",                             True),
    ("RPL_CODE_DIO, pos)",               "RPL_SEC_ON_DIO_TX();",                             True),
    ("RPL_CODE_DAO, pos)",               "RPL_SEC_ON_DAO_TX();",                             True),
]


def indent_of(line):
    return line[:len(line) - len(line.lstrip())]


def main():
    if len(sys.argv) != 2:
        print("usage: python3 add_instrumentation_hooks.py <path-to-rpl-icmp6.c>")
        return 2
    path = sys.argv[1]

    try:
        with open(path) as f:
            text = f.read()
    except OSError as e:
        print("ERROR: cannot read %s (%s)" % (path, e))
        return 1

    if "RPL_SEC_ON_DIO_RX" in text:
        print("Already patched: the instrumentation hooks are present. Nothing to do.")
        return 0

    # 1. Verify the macro anchor exists exactly once.
    if text.count(MACRO_ANCHOR) != 1:
        print("ERROR: could not find the RPL_DIO_VERSION_HOOK macro block exactly once.")
        print("This file may not have the base hooks, or is an unexpected version.")
        return 1

    # 2. Verify every call-site anchor matches exactly one line.
    lines = text.splitlines(keepends=True)
    plan = []  # (line_index, hook_text, before)
    for needle, hook, before in CALL_SITES:
        idx = [i for i, ln in enumerate(lines) if needle in ln]
        if len(idx) != 1:
            print("ERROR: anchor %r matched %d lines (expected 1). Aborting; file untouched."
                  % (needle, len(idx)))
            return 1
        plan.append((idx[0], hook, before))

    # All anchors good. Back up, then apply.
    shutil.copyfile(path, path + ".bak")

    # Insert the macro block (string level, before touching line list again).
    text = text.replace(MACRO_ANCHOR, MACRO_ANCHOR + MACRO_BLOCK, 1)

    # Re-split and insert call sites, working from the bottom up so earlier
    # indices stay valid.
    lines = text.splitlines(keepends=True)
    # Recompute indices against the new text for the call sites.
    plan = []
    for needle, hook, before in CALL_SITES:
        idx = [i for i, ln in enumerate(lines) if needle in ln]
        plan.append((idx[0], hook, before))
    for idx, hook, before in sorted(plan, key=lambda t: t[0], reverse=True):
        pad = indent_of(lines[idx])
        insert_at = idx if before else idx + 1
        lines.insert(insert_at, pad + hook + "\n")

    with open(path, "w") as f:
        f.write("".join(lines))

    print("Done. Inserted 5 macro definitions and 5 call sites.")
    print("Backup written to %s.bak" % path)
    print("Verify with:  grep -c RPL_SEC_ON_ %s   (expect 15)" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
