#!/usr/bin/env python3
"""
TPMS Unknown Signal Analyzer
Analyzes captured unknown signals to determine if there's enough data
for protocol identification and sensor ID extraction.

Usage:
    uv run tpms-decode                  # full report
    uv run tpms-decode fingerprints     # group by fingerprint
    uv run tpms-decode compare <fp>     # compare captures within a fingerprint
    uv run tpms-decode candidates       # show signals likely to be TPMS
    uv run tpms-decode iq               # list saved IQ files for replay
"""

import sqlite3
import sys
import os
from pathlib import Path
from collections import defaultdict

DB_PATH = Path(__file__).parent / "tpms_data.db"
IQ_DIR = Path(__file__).parent / "unknown_iq"

# TPMS signals typically have these characteristics
TPMS_PULSE_RANGE = (40, 120)     # pulse count
TPMS_WIDTH_RANGE = (5.0, 20.0)  # total width in ms
TPMS_MODULATIONS = {"OOK", "FSK", "FSK_PCM", "PCM", "ASK", "PPM", "PWM",
                    "MANCHESTER", "MC", "DMC"}


def get_db():
    if not DB_PATH.exists():
        print(f"No database at {DB_PATH}. Run tpms_capture first.")
        sys.exit(1)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def report():
    """Full readiness report."""
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM unknown_signals").fetchone()[0]
    with_hex = db.execute("SELECT COUNT(*) FROM unknown_signals WHERE raw_hex IS NOT NULL AND raw_hex != ''").fetchone()[0]
    unique_fps = db.execute("SELECT COUNT(DISTINCT fingerprint) FROM unknown_signals WHERE fingerprint IS NOT NULL AND fingerprint != ''").fetchone()[0]

    # Group by fingerprint
    groups = db.execute("""
        SELECT fingerprint, modulation, pulse_count, width_ms,
               COUNT(*) as captures, frequency_label
        FROM unknown_signals
        WHERE fingerprint IS NOT NULL AND fingerprint != ''
        GROUP BY fingerprint
        ORDER BY captures DESC
    """).fetchall()

    print("=" * 70)
    print("  Unknown Signal Analysis Report")
    print("=" * 70)
    print(f"  Total unknown captures:  {total}")
    print(f"  With raw hex data:       {with_hex}")
    print(f"  Unique fingerprints:     {unique_fps}")
    print()

    if not groups:
        print("  No fingerprinted signals yet. Keep the capture tool running")
        print("  near a road — unknown signals will accumulate over time.")
        print()
        print("  Tip: TPMS sensors typically transmit every 30-60 seconds")
        print("  when the vehicle is moving, and every few minutes when parked.")
        return

    # Classify each fingerprint
    print(f"  {'FP':<18} {'Mod':<8} {'Pulses':>6} {'Width':>8} {'Captures':>8}  {'Assessment'}")
    print(f"  {'-'*18} {'-'*8} {'-'*6} {'-'*8} {'-'*8}  {'-'*30}")

    tpms_candidates = []
    for g in groups:
        fp = g["fingerprint"] or "?"
        mod = g["modulation"] or "?"
        pc = g["pulse_count"]
        wms = g["width_ms"]
        caps = g["captures"]

        # Assess likelihood of being TPMS
        assessment = assess_tpms_likelihood(pc, wms, mod)
        marker = ""
        if "LIKELY TPMS" in assessment:
            marker = " <<<"
            tpms_candidates.append(g)

        print(f"  {fp:<18} {mod:<8} {pc or '?':>6} {f'{wms:.1f}ms' if wms else '?':>8} {caps:>8}  {assessment}{marker}")

    print()

    # Readiness assessment
    print("-" * 70)
    print("  Decoding Readiness")
    print("-" * 70)
    for g in groups:
        fp = g["fingerprint"]
        caps = g["captures"]
        has_hex = db.execute(
            "SELECT COUNT(*) FROM unknown_signals WHERE fingerprint = ? AND raw_hex IS NOT NULL AND raw_hex != ''",
            (fp,)
        ).fetchone()[0]

        status = "NEEDS MORE DATA"
        advice = ""

        if caps >= 5 and has_hex >= 3:
            status = "READY TO ANALYZE"
            advice = "Run: uv run tpms-decode compare " + fp
        elif caps >= 3 and has_hex >= 2:
            status = "ALMOST READY"
            advice = f"Need {max(0, 5 - caps)} more captures with hex data"
        elif caps >= 2:
            status = "COLLECTING"
            if has_hex == 0:
                advice = "Have pulse data but no bitstream yet — parser may need tuning"
            else:
                advice = f"Need {max(0, 5 - caps)} more captures"
        else:
            advice = f"Only {caps} capture(s) — need at least 3-5 for comparison"

        pc = g["pulse_count"]
        mod = g["modulation"] or "?"
        print(f"  {fp[:16]}  {mod:<8} {pc or '?':>3}p  [{status}]  {advice}")

    if tpms_candidates:
        print()
        print("-" * 70)
        print("  TPMS Candidates")
        print("-" * 70)
        print("  These fingerprints have characteristics consistent with TPMS:")
        for g in tpms_candidates:
            print(f"    {g['fingerprint']}  {g['modulation'] or '?'} {g['pulse_count'] or '?'}p  ({g['captures']} captures)")
        print()
        print("  To analyze: uv run tpms-decode compare <fingerprint>")

    # Check for IQ files
    iq_files = list(IQ_DIR.glob("*.cu8")) if IQ_DIR.exists() else []
    if iq_files:
        print()
        print(f"  Raw IQ files saved: {len(iq_files)} (in {IQ_DIR}/)")
        print(f"  Replay with: rtl_433 -r <filename> -A")

    print()
    print("=" * 70)
    print()
    print("  Online tools for protocol analysis:")
    print("    - https://triq.org/pdv/           Pulse data visualizer")
    print("    - https://triq.net/bitbench       Bit pattern analyzer")
    print("    - https://github.com/merbanan/rtl_433/wiki")
    print()
    print("  Workflow:")
    print("    1. Collect 5+ captures of the same fingerprint")
    print("    2. Run: uv run tpms-decode compare <fingerprint>")
    print("    3. Look for constant bytes (= sensor ID) vs changing (= data)")
    print("    4. Use triq.org to visualize the pulse pattern")
    print("    5. Write a flex decoder in flex_decoders/<name>.conf")
    print("    6. Test: rtl_433 -r unknown_iq/<file>.cu8 -c flex_decoders/<name>.conf")
    print()

    db.close()


def assess_tpms_likelihood(pulse_count, width_ms, modulation):
    """Assess how likely a signal is to be TPMS based on characteristics."""
    if pulse_count is None or width_ms is None:
        return "Insufficient data"

    score = 0
    reasons = []

    # Pulse count: TPMS typically 40-120 pulses
    if TPMS_PULSE_RANGE[0] <= pulse_count <= TPMS_PULSE_RANGE[1]:
        score += 3
        reasons.append("pulse count in TPMS range")
    elif 20 <= pulse_count <= 150:
        score += 1
        reasons.append("pulse count possible")
    else:
        reasons.append(f"unusual pulse count ({pulse_count})")

    # Width: TPMS typically 5-20ms
    if TPMS_WIDTH_RANGE[0] <= width_ms <= TPMS_WIDTH_RANGE[1]:
        score += 3
        reasons.append("width in TPMS range")
    elif 2.0 <= width_ms <= 30.0:
        score += 1
    else:
        reasons.append(f"unusual width ({width_ms:.1f}ms)")

    # Modulation
    if modulation and modulation.upper() in TPMS_MODULATIONS:
        score += 2
        reasons.append(f"{modulation}")
    elif not modulation:
        score += 1  # neutral

    # Very short signals are likely noise
    if pulse_count <= 3 or width_ms < 0.5:
        return "Likely noise/interference"

    if score >= 6:
        return "LIKELY TPMS — " + ", ".join(reasons)
    elif score >= 4:
        return "Possible TPMS — " + ", ".join(reasons)
    elif score >= 2:
        return "Uncertain — " + ", ".join(reasons)
    else:
        return "Unlikely TPMS — " + ", ".join(reasons)


def fingerprints():
    """List all fingerprints with capture counts."""
    db = get_db()
    groups = db.execute("""
        SELECT fingerprint, modulation, pulse_count, width_ms,
               COUNT(*) as captures, frequency_label,
               MIN(timestamp) as first, MAX(timestamp) as last
        FROM unknown_signals
        WHERE fingerprint IS NOT NULL AND fingerprint != ''
        GROUP BY fingerprint
        ORDER BY captures DESC
    """).fetchall()

    if not groups:
        print("No fingerprinted signals yet.")
        return

    print(f"{'Fingerprint':<18} {'Mod':<10} {'Pulses':>6} {'Width':>8} {'Caps':>5} {'Band':<8} {'First Seen':<26} {'Last Seen'}")
    print("-" * 120)
    for g in groups:
        w = f"{g['width_ms']:.1f}ms" if g['width_ms'] else "?"
        print(f"{g['fingerprint'] or '?':<18} "
              f"{g['modulation'] or '?':<10} "
              f"{g['pulse_count'] or '?':>6} "
              f"{w:>8} "
              f"{g['captures']:>5} "
              f"{g['frequency_label'] or '?':<8} "
              f"{g['first']:<26} "
              f"{g['last']}")

    db.close()


def compare(fp):
    """Compare all captures with a given fingerprint to find constant vs variable bytes."""
    db = get_db()
    rows = db.execute(
        "SELECT id, timestamp, raw_hex, analysis_text FROM unknown_signals WHERE fingerprint = ? ORDER BY timestamp",
        (fp,)
    ).fetchall()

    if not rows:
        print(f"No captures found for fingerprint {fp}")
        return

    print(f"Fingerprint: {fp}")
    print(f"Captures:    {len(rows)}")
    print()

    # Show all raw hex side by side
    hex_data = []
    for r in rows:
        print(f"  #{r['id']:>4}  {r['timestamp']}  hex: {r['raw_hex'] or 'NONE'}")
        if r['raw_hex']:
            hex_data.append(r['raw_hex'])

    if len(hex_data) < 2:
        print()
        print(f"  Need at least 2 captures WITH raw hex data to compare.")
        print(f"  Have {len(hex_data)} with hex out of {len(rows)} total.")
        print(f"  Keep capturing — the parser may need the demodulation")
        print(f"  portion of the analysis output to extract hex.")
        print()
        print(f"  You can try replaying IQ files manually:")
        iq_files = list(IQ_DIR.glob("*.cu8")) if IQ_DIR.exists() else []
        if iq_files:
            print(f"    rtl_433 -r {iq_files[0]} -A")
        return

    print()
    print("  Byte-level comparison (constant = likely ID, changing = data):")
    print("  " + "-" * 60)

    # Split hex into bytes and compare
    byte_arrays = []
    for hx in hex_data:
        # Handle different formats: "ab cd ef" or "[00]{68} ab cd ef"
        # Strip bitbuffer prefixes
        clean = hx
        for part in clean.split("||"):
            part = part.strip()
            # Remove [XX]{YY} prefix
            if part.startswith("["):
                idx = part.find("}")
                if idx >= 0:
                    part = part[idx+1:].strip()
            bytes_list = part.split()
            byte_arrays.append(bytes_list)
            break  # just use first row for now

    if not byte_arrays:
        print("  Could not parse hex data for comparison.")
        return

    # Find the shortest for alignment
    min_len = min(len(ba) for ba in byte_arrays)
    if min_len == 0:
        print("  No byte data to compare.")
        return

    # Compare each byte position
    constant_bytes = []
    variable_bytes = []
    for i in range(min_len):
        values = set(ba[i].lower() for ba in byte_arrays if i < len(ba))
        if len(values) == 1:
            constant_bytes.append((i, list(values)[0]))
        else:
            variable_bytes.append((i, values))

    print(f"  Total bytes compared: {min_len} (across {len(byte_arrays)} captures)")
    print()
    print(f"  CONSTANT bytes (likely sensor ID):")
    if constant_bytes:
        id_hex = " ".join(v for _, v in constant_bytes)
        positions = ", ".join(str(p) for p, _ in constant_bytes)
        print(f"    Positions: {positions}")
        print(f"    Values:    {id_hex}")
        print(f"    Candidate ID: {id_hex.replace(' ', '').upper()}")
    else:
        print(f"    None found — all bytes differ (may need more captures)")

    print()
    print(f"  VARIABLE bytes (likely pressure/temp/flags):")
    if variable_bytes:
        for pos, vals in variable_bytes:
            vals_str = ", ".join(sorted(vals))
            print(f"    Byte {pos}: {vals_str}")
    else:
        print(f"    None — all bytes are constant (odd, may be same exact reading)")

    print()
    if constant_bytes and variable_bytes:
        print(f"  This looks decodable! Possible sensor ID: "
              f"{''.join(v for _, v in constant_bytes).upper()}")
        print(f"  Next steps:")
        print(f"    1. Visit triq.org/pdv/ and paste the hex data to visualize")
        print(f"    2. Use triq.net/bitbench to analyze the bit pattern")
        print(f"    3. Create a flex decoder in flex_decoders/unknown_{fp[:8]}.conf")
    elif len(hex_data) < 5:
        print(f"  Need more captures for reliable comparison (have {len(hex_data)}, want 5+)")

    db.close()


def candidates():
    """Show signals most likely to be TPMS."""
    db = get_db()
    groups = db.execute("""
        SELECT fingerprint, modulation, pulse_count, width_ms,
               COUNT(*) as captures, frequency_label
        FROM unknown_signals
        WHERE fingerprint IS NOT NULL AND fingerprint != ''
          AND pulse_count IS NOT NULL
        GROUP BY fingerprint
        ORDER BY captures DESC
    """).fetchall()

    print("TPMS Candidates (ranked by likelihood):")
    print()

    ranked = []
    for g in groups:
        assessment = assess_tpms_likelihood(g["pulse_count"], g["width_ms"], g["modulation"])
        if "noise" in assessment.lower():
            continue
        ranked.append((g, assessment))

    # Sort: LIKELY first, then by capture count
    def sort_key(item):
        g, a = item
        if "LIKELY" in a:
            return (0, -g["captures"])
        elif "Possible" in a:
            return (1, -g["captures"])
        else:
            return (2, -g["captures"])

    ranked.sort(key=sort_key)

    if not ranked:
        print("  No candidates yet. Keep capturing!")
        return

    for g, assessment in ranked:
        print(f"  {g['fingerprint']:<18} {g['modulation'] or '?':<8} "
              f"{g['pulse_count']:>3}p {g['width_ms']:.1f}ms  "
              f"{g['captures']:>3} captures  {assessment}")

    db.close()


def list_iq():
    """List saved IQ files."""
    if not IQ_DIR.exists():
        print(f"No IQ directory at {IQ_DIR}")
        return

    files = sorted(IQ_DIR.glob("*.cu8"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not files:
        print("No IQ files saved yet.")
        return

    print(f"Saved IQ files ({len(files)} total):")
    print(f"{'File':<50} {'Size':>10} {'Modified'}")
    print("-" * 80)
    for f in files[:50]:
        size = f.stat().st_size
        if size > 1024 * 1024:
            size_str = f"{size / 1024 / 1024:.1f} MB"
        elif size > 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size} B"
        mtime = os.path.getmtime(f)
        from datetime import datetime
        mt = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  {f.name:<48} {size_str:>10} {mt}")

    print()
    print("Replay a file:  rtl_433 -r <filename> -A")
    print("Test a decoder:  rtl_433 -r <filename> -c flex_decoders/<name>.conf")


def main():
    if len(sys.argv) < 2:
        report()
    elif sys.argv[1] == "fingerprints":
        fingerprints()
    elif sys.argv[1] == "compare" and len(sys.argv) > 2:
        compare(sys.argv[2])
    elif sys.argv[1] == "candidates":
        candidates()
    elif sys.argv[1] == "iq":
        list_iq()
    else:
        print("Usage:")
        print("  uv run tpms-decode                  Full readiness report")
        print("  uv run tpms-decode fingerprints      List all fingerprints")
        print("  uv run tpms-decode compare <fp>      Compare captures for ID extraction")
        print("  uv run tpms-decode candidates        Show likely TPMS signals")
        print("  uv run tpms-decode iq                List saved IQ files")


if __name__ == "__main__":
    main()
