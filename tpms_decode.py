#!/usr/bin/env python3
"""
TPMS Unknown Signal Analyzer
Analyzes captured unknown signals to determine if there's enough data
for protocol identification and sensor ID extraction.

Usage:
    uv run tpms-decode                  # full report with fuzzy clustering
    uv run tpms-decode clusters         # show protocol clusters
    uv run tpms-decode compare <group>  # compare captures within a cluster
    uv run tpms-decode candidates       # show signals likely to be TPMS
    uv run tpms-decode reprint          # recompute fingerprints with bucketing
"""

import hashlib
import re
import sqlite3
import sys
from pathlib import Path
from collections import defaultdict

DB_PATH = Path(__file__).parent / "tpms_data.db"

# TPMS signals typically have these characteristics
TPMS_PULSE_RANGE = (30, 120)     # pulse count
TPMS_WIDTH_RANGE = (5.0, 25.0)   # total width in ms
TPMS_MODULATIONS = {"OOK", "FSK", "FSK_PCM", "PCM", "ASK", "PPM", "PWM",
                    "MANCHESTER", "MC", "DMC"}


def get_db():
    if not DB_PATH.exists():
        print(f"No database at {DB_PATH}. Run tpms_capture first.")
        sys.exit(1)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


# ── Fuzzy clustering ────────────────────────────────────────────────────────

def compute_bucket_fp(pulse_count, width_ms, modulation):
    """Compute a bucketed fingerprint for fuzzy grouping.

    Pulse count bucketed to nearest 5, width to nearest 1ms,
    ms-per-pulse ratio bucketed to nearest 0.05ms.
    """
    if pulse_count and width_ms and pulse_count > 0:
        ms_per_pulse = round(width_ms / pulse_count * 20) / 20
        pc_bucket = round(pulse_count / 5) * 5
        w_bucket = round(width_ms)
        fp_input = f"{modulation or '?'}:{pc_bucket}:{w_bucket}:{ms_per_pulse}"
    else:
        fp_input = f"{modulation or '?'}:{pulse_count or '?'}:{width_ms or '?'}"
    return hashlib.sha256(fp_input.encode()).hexdigest()[:16]


def cluster_signals(rows):
    """Group signals into protocol clusters using ms-per-pulse ratio.

    Two signals are in the same cluster if:
    - ms-per-pulse ratios are within 20% of each other
    - Pulse counts are within 30% of each other
    """
    clusters = []  # list of (centroid_dict, [row_list])

    for row in rows:
        pc = row["pulse_count"]
        wms = row["width_ms"]
        if not pc or not wms or pc <= 0:
            continue

        mpp = wms / pc  # ms per pulse

        # Find matching cluster
        matched = False
        for centroid, members in clusters:
            c_mpp = centroid["mpp"]
            c_pc = centroid["pulse_count"]

            # Check ms-per-pulse ratio similarity (within 20%)
            if c_mpp > 0 and abs(mpp - c_mpp) / c_mpp < 0.20:
                # Also check pulse count similarity (within 30%)
                if abs(pc - c_pc) / c_pc < 0.30:
                    members.append(row)
                    # Update centroid as running average
                    n = len(members)
                    centroid["mpp"] = (centroid["mpp"] * (n-1) + mpp) / n
                    centroid["pulse_count"] = (centroid["pulse_count"] * (n-1) + pc) / n
                    centroid["width_ms"] = (centroid["width_ms"] * (n-1) + wms) / n
                    matched = True
                    break

        if not matched:
            clusters.append((
                {"mpp": mpp, "pulse_count": pc, "width_ms": wms,
                 "modulation": row["modulation"]},
                [row]
            ))

    # Sort by member count descending
    clusters.sort(key=lambda x: len(x[1]), reverse=True)

    # Assign group labels
    labeled = []
    for i, (centroid, members) in enumerate(clusters):
        label = f"G{i+1:02d}"
        labeled.append((label, centroid, members))

    return labeled


def assess_tpms_likelihood(pulse_count, width_ms, modulation):
    """Assess how likely a signal cluster is to be TPMS."""
    if pulse_count is None or width_ms is None:
        return "Insufficient data", 0

    score = 0
    reasons = []

    if TPMS_PULSE_RANGE[0] <= pulse_count <= TPMS_PULSE_RANGE[1]:
        score += 3
        reasons.append("pulse count in TPMS range")
    elif 20 <= pulse_count <= 150:
        score += 1
    else:
        reasons.append(f"unusual pulse count ({pulse_count:.0f})")

    if TPMS_WIDTH_RANGE[0] <= width_ms <= TPMS_WIDTH_RANGE[1]:
        score += 3
        reasons.append("width in TPMS range")
    elif 2.0 <= width_ms <= 50.0:
        score += 1
    else:
        reasons.append(f"unusual width ({width_ms:.1f}ms)")

    if modulation and modulation.upper() in TPMS_MODULATIONS:
        score += 2
        reasons.append(modulation)

    if pulse_count <= 5 or width_ms < 0.5:
        return "Likely noise/interference", 0

    if score >= 6:
        return "LIKELY TPMS — " + ", ".join(reasons), score
    elif score >= 4:
        return "Possible TPMS — " + ", ".join(reasons), score
    elif score >= 2:
        return "Uncertain — " + ", ".join(reasons), score
    else:
        return "Unlikely TPMS — " + ", ".join(reasons), score


# ── Commands ────────────────────────────────────────────────────────────────

def report():
    """Full report with fuzzy clustering."""
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM unknown_signals").fetchone()[0]

    rows = db.execute("""
        SELECT * FROM unknown_signals
        WHERE pulse_count IS NOT NULL AND pulse_count > 5
        ORDER BY timestamp
    """).fetchall()

    clusters = cluster_signals(rows)

    print("=" * 78)
    print("  Unknown Signal Analysis Report")
    print("=" * 78)
    print(f"  Total unknown captures:  {total}")
    print(f"  Analyzable (>5 pulses):  {len(rows)}")
    print(f"  Protocol clusters found: {len(clusters)}")
    print()

    if not clusters:
        print("  No analyzable signals yet. Keep the capture tool running.")
        return

    # Show clusters
    print(f"  {'Group':<6} {'Captures':>8}  {'Avg Pulses':>10}  {'Avg Width':>10}  "
          f"{'ms/pulse':>8}  {'Mod':<8}  {'Assessment'}")
    print(f"  {'-'*6} {'-'*8}  {'-'*10}  {'-'*10}  {'-'*8}  {'-'*8}  {'-'*30}")

    tpms_groups = []
    for label, centroid, members in clusters:
        pc = centroid["pulse_count"]
        wms = centroid["width_ms"]
        mpp = centroid["mpp"]
        mod = centroid["modulation"] or "?"
        assessment, score = assess_tpms_likelihood(pc, wms, mod)

        marker = ""
        if "LIKELY" in assessment:
            marker = " <<<"
            tpms_groups.append((label, centroid, members, assessment))

        print(f"  {label:<6} {len(members):>8}  {pc:>10.1f}  {wms:>9.1f}ms  "
              f"{mpp:>7.2f}  {mod:<8}  {assessment}{marker}")

    # Readiness assessment
    print()
    print("-" * 78)
    print("  Decoding Readiness")
    print("-" * 78)

    for label, centroid, members, *_ in clusters:
        n = len(members)
        has_hex = sum(1 for m in members if m["raw_hex"])

        if n >= 5 and has_hex >= 3:
            status = "\033[32mREADY TO ANALYZE\033[0m"
        elif n >= 5:
            status = "\033[33mHAVE DATA — need hex\033[0m"
        elif n >= 3:
            status = "\033[33mALMOST READY\033[0m"
        elif n >= 2:
            status = "COLLECTING"
        else:
            status = "\033[2mNEED MORE DATA\033[0m"

        pc = centroid["pulse_count"]
        mpp = centroid["mpp"]

        # Show pulse count range in this cluster
        pcs = [m["pulse_count"] for m in members]
        pc_range = f"{min(pcs)}-{max(pcs)}" if len(pcs) > 1 else str(pcs[0])

        print(f"  {label}  {pc_range:>7}p  {mpp:.2f}ms/p  "
              f"{n:>3} captures  {has_hex:>2} with hex  [{status}]")

    if tpms_groups:
        print()
        print("-" * 78)
        print("  TPMS Candidates — Recommended Actions")
        print("-" * 78)
        for label, centroid, members, assessment in tpms_groups:
            n = len(members)
            print(f"\n  {label}: {n} captures, {centroid['pulse_count']:.0f}p avg, "
                  f"{centroid['mpp']:.2f}ms/pulse")
            if n >= 5:
                print(f"    >>> Run: uv run tpms-decode compare {label}")
            elif n >= 2:
                print(f"    >>> Getting close! {5-n} more captures needed.")
                print(f"    >>> Run: uv run tpms-decode compare {label}  (to see what you have)")
            else:
                print(f"    >>> Need more captures. Keep monitoring.")

    print()
    print("=" * 78)
    print()
    print("  Online tools:")
    print("    https://triq.org/pdv/        Pulse data visualizer")
    print("    https://triq.net/bitbench    Bit pattern analyzer")
    print()
    print("  Commands:")
    print("    uv run tpms-decode clusters         Show protocol clusters")
    print("    uv run tpms-decode compare <group>   Compare captures (e.g. G01)")
    print("    uv run tpms-decode candidates        Ranked TPMS candidates")
    print("    uv run tpms-decode reprint           Recompute fingerprints")
    print()

    db.close()


def show_clusters():
    """Show all clusters with their member signals."""
    db = get_db()
    rows = db.execute("""
        SELECT * FROM unknown_signals
        WHERE pulse_count IS NOT NULL AND pulse_count > 5
        ORDER BY timestamp
    """).fetchall()

    clusters = cluster_signals(rows)

    for label, centroid, members in clusters:
        pc = centroid["pulse_count"]
        mpp = centroid["mpp"]
        assessment, _ = assess_tpms_likelihood(pc, centroid["width_ms"], centroid["modulation"])

        print(f"\n{'='*60}")
        print(f"  {label}: {len(members)} captures — {assessment}")
        print(f"  Avg: {pc:.0f} pulses, {centroid['width_ms']:.1f}ms, "
              f"{mpp:.3f}ms/pulse, mod={centroid['modulation'] or '?'}")
        print(f"{'='*60}")

        print(f"  {'ID':>5}  {'Timestamp':<26}  {'Band':<7}  {'Pulses':>6}  {'Width':>8}  {'ms/p':>6}  {'Hex'}")
        print(f"  {'-'*5}  {'-'*26}  {'-'*7}  {'-'*6}  {'-'*8}  {'-'*6}  {'-'*30}")

        for m in members:
            mpp_i = m["width_ms"] / m["pulse_count"] if m["pulse_count"] > 0 else 0
            hex_preview = (m["raw_hex"][:30] + "...") if m["raw_hex"] and len(m["raw_hex"]) > 30 else (m["raw_hex"] or "-")
            print(f"  {m['id']:>5}  {m['timestamp']:<26}  {m['frequency_label'] or '?':<7}  "
                  f"{m['pulse_count']:>6}  {m['width_ms']:>7.1f}  {mpp_i:>5.2f}  {hex_preview}")

    db.close()


def compare(group_label):
    """Compare all captures in a cluster group."""
    db = get_db()
    rows = db.execute("""
        SELECT * FROM unknown_signals
        WHERE pulse_count IS NOT NULL AND pulse_count > 5
        ORDER BY timestamp
    """).fetchall()

    clusters = cluster_signals(rows)

    # Find the requested group
    target = None
    for label, centroid, members in clusters:
        if label.upper() == group_label.upper():
            target = (label, centroid, members)
            break

    if not target:
        print(f"Group '{group_label}' not found. Available groups:")
        for label, _, members in clusters:
            print(f"  {label}: {len(members)} captures")
        return

    label, centroid, members = target
    print(f"Group {label}: {len(members)} captures")
    print(f"  Avg: {centroid['pulse_count']:.0f} pulses, {centroid['width_ms']:.1f}ms, "
          f"{centroid['mpp']:.3f}ms/pulse")
    print()

    # Show pulse width distributions side by side
    print("Pulse timing comparison:")
    print("-" * 70)

    for m in members:
        mpp = m["width_ms"] / m["pulse_count"] if m["pulse_count"] > 0 else 0
        print(f"  #{m['id']:>4}  {m['timestamp'][:19]}  {m['pulse_count']:>3}p  "
              f"{m['width_ms']:.1f}ms  {mpp:.3f}ms/p  hex:{m['raw_hex'] or 'none'}")

    # Compare pulse width distributions from analysis text
    print()
    print("Pulse width distributions:")
    print("-" * 70)

    distributions = []
    for m in members:
        text = m["analysis_text"] or ""
        in_pulse_dist = False
        pulse_dist = []
        for line in text.split("\n"):
            if "Pulse width distribution" in line:
                in_pulse_dist = True
                continue
            elif "Gap width distribution" in line:
                in_pulse_dist = False
                continue
            if in_pulse_dist:
                match = re.search(r"count:\s*(\d+),\s*width:\s*(\d+)\s*us", line)
                if match:
                    pulse_dist.append((int(match.group(1)), int(match.group(2))))

        distributions.append((m["id"], pulse_dist))
        if pulse_dist:
            dist_str = ", ".join(f"{cnt}x{w}us" for cnt, w in pulse_dist)
            print(f"  #{m['id']:>4}: {dist_str}")

    # Check if distributions match (same protocol)
    if len(distributions) >= 2:
        # Compare number of pulse width bins
        bin_counts = [len(d) for _, d in distributions if d]
        if bin_counts:
            if len(set(bin_counts)) == 1:
                print(f"\n  All captures have {bin_counts[0]} pulse width bins — likely same protocol")
            else:
                print(f"\n  Varying bin counts ({set(bin_counts)}) — may be mixed protocols")

    # Raw hex comparison
    hex_data = [(m["id"], m["raw_hex"]) for m in members if m["raw_hex"]]

    if len(hex_data) >= 2:
        print()
        print("Raw hex byte comparison:")
        print("-" * 70)

        byte_arrays = []
        for mid, hx in hex_data:
            clean = hx.split("||")[0].strip()
            if clean.startswith("["):
                idx = clean.find("}")
                if idx >= 0:
                    clean = clean[idx+1:].strip()
            byte_arrays.append((mid, clean.split()))

        if byte_arrays:
            min_len = min(len(ba) for _, ba in byte_arrays)

            constant = []
            variable = []
            for i in range(min_len):
                vals = set(ba[i].lower() for _, ba in byte_arrays if i < len(ba))
                if len(vals) == 1:
                    constant.append((i, list(vals)[0]))
                else:
                    variable.append((i, vals))

            if constant:
                id_hex = " ".join(v for _, v in constant)
                print(f"  CONSTANT bytes (candidate sensor ID): {id_hex}")
                print(f"  Candidate ID: {id_hex.replace(' ', '').upper()}")
            if variable:
                print(f"  VARIABLE bytes (data payload):")
                for pos, vals in variable:
                    print(f"    Byte {pos}: {', '.join(sorted(vals))}")
    elif hex_data:
        print(f"\n  Only {len(hex_data)} capture(s) with hex data — need 2+ for comparison.")
    else:
        print(f"\n  No raw hex captured yet for this group.")
        print(f"  The pulse analysis data above can still identify the protocol.")
        print(f"  Try pasting the pulse widths into https://triq.org/pdv/")

    # Show full analysis text for the first capture
    if members:
        print()
        print(f"Full analysis (capture #{members[0]['id']}):")
        print("-" * 70)
        text = members[0]["analysis_text"] or "No analysis text"
        for line in text.split("\n"):
            print(f"  {line}")

    db.close()


def candidates():
    """Show clusters ranked by TPMS likelihood."""
    db = get_db()
    rows = db.execute("""
        SELECT * FROM unknown_signals
        WHERE pulse_count IS NOT NULL AND pulse_count > 5
        ORDER BY timestamp
    """).fetchall()

    clusters = cluster_signals(rows)

    print("TPMS Candidates (ranked by likelihood):")
    print()

    ranked = []
    for label, centroid, members in clusters:
        assessment, score = assess_tpms_likelihood(
            centroid["pulse_count"], centroid["width_ms"], centroid["modulation"]
        )
        if "noise" in assessment.lower():
            continue
        ranked.append((label, centroid, members, assessment, score))

    ranked.sort(key=lambda x: (-x[4], -len(x[2])))

    if not ranked:
        print("  No candidates yet. Keep capturing!")
        return

    for label, centroid, members, assessment, score in ranked:
        pcs = [m["pulse_count"] for m in members]
        pc_range = f"{min(pcs)}-{max(pcs)}" if len(set(pcs)) > 1 else str(pcs[0])
        print(f"  {label}  {pc_range:>7}p  {centroid['mpp']:.2f}ms/p  "
              f"{len(members):>3} captures  {assessment}")

    db.close()


def reprint():
    """Recompute fingerprints for all existing unknown signals using bucketed values."""
    db = get_db()
    rows = db.execute("SELECT id, pulse_count, width_ms, modulation FROM unknown_signals").fetchall()

    updated = 0
    for r in rows:
        new_fp = compute_bucket_fp(r["pulse_count"], r["width_ms"], r["modulation"])
        db.execute("UPDATE unknown_signals SET fingerprint = ? WHERE id = ?", (new_fp, r["id"]))
        updated += 1

    db.commit()
    print(f"Recomputed fingerprints for {updated} signals.")

    # Show how many unique fingerprints we have now
    unique = db.execute("SELECT COUNT(DISTINCT fingerprint) FROM unknown_signals").fetchone()[0]
    print(f"Unique fingerprints: {unique} (was likely more before bucketing)")

    db.close()


def main():
    if len(sys.argv) < 2:
        report()
    elif sys.argv[1] == "clusters":
        show_clusters()
    elif sys.argv[1] == "compare" and len(sys.argv) > 2:
        compare(sys.argv[2])
    elif sys.argv[1] == "candidates":
        candidates()
    elif sys.argv[1] == "reprint":
        reprint()
    else:
        print("Usage:")
        print("  uv run tpms-decode                  Full report with fuzzy clustering")
        print("  uv run tpms-decode clusters          Show all protocol clusters in detail")
        print("  uv run tpms-decode compare <group>   Compare captures (e.g. G01)")
        print("  uv run tpms-decode candidates        Ranked TPMS candidates")
        print("  uv run tpms-decode reprint           Recompute fingerprints with bucketing")


if __name__ == "__main__":
    main()
