#!/usr/bin/env python3
"""
TPMS Data Analysis Tool
Analyzes captured TPMS data for anti-stalking research.

Key metrics for the paper:
- How many unique vehicles pass in a given time window
- Re-identification rate (same sensor IDs appearing on different days/times)
- How far apart sightings of the same vehicle occur
- Sensor protocol distribution (what % of traffic is trackable)
"""

import sqlite3
import json
import sys
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

DB_PATH = Path(__file__).parent / "tpms_data.db"


def get_conn():
    if not DB_PATH.exists():
        print(f"No database found at {DB_PATH}. Run tpms_capture.py first.")
        sys.exit(1)
    return sqlite3.connect(str(DB_PATH))


def overview(conn):
    """Print high-level stats."""
    cur = conn.execute("SELECT COUNT(*) FROM readings")
    total = cur.fetchone()[0]

    cur = conn.execute("SELECT COUNT(DISTINCT sensor_id) FROM readings")
    unique_sensors = cur.fetchone()[0]

    cur = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM readings")
    first, last = cur.fetchone()

    cur = conn.execute("""
        SELECT model, COUNT(*) as cnt, COUNT(DISTINCT sensor_id) as sensors
        FROM readings GROUP BY model ORDER BY cnt DESC
    """)
    models = cur.fetchall()

    print("=" * 70)
    print("TPMS Capture Overview")
    print("=" * 70)
    print(f"Total readings:      {total}")
    print(f"Unique sensor IDs:   {unique_sensors}")
    print(f"Estimated vehicles:  ~{unique_sensors // 4} (assuming 4 sensors/vehicle)")
    print(f"First reading:       {first}")
    print(f"Last reading:        {last}")

    if first and last:
        t0 = datetime.fromisoformat(first)
        t1 = datetime.fromisoformat(last)
        hours = (t1 - t0).total_seconds() / 3600
        if hours > 0:
            print(f"Capture duration:    {hours:.1f} hours")
            print(f"Sensors/hour:        {unique_sensors / hours:.1f}")

    print(f"\nProtocol breakdown:")
    print(f"  {'Model':<40} {'Readings':>8} {'Sensors':>8}")
    print(f"  {'-'*40} {'-'*8} {'-'*8}")
    for model, cnt, sensors in models:
        print(f"  {model:<40} {cnt:>8} {sensors:>8}")


def repeat_visitors(conn):
    """Find sensor IDs that appear across multiple time windows.
    This is the key anti-stalking metric — how trackable is a vehicle?"""
    print("\n" + "=" * 70)
    print("Repeat Visitors (Re-identification Analysis)")
    print("=" * 70)

    # Group readings into 1-hour windows and find sensors seen in multiple windows
    cur = conn.execute("""
        SELECT sensor_id, model,
               COUNT(*) as total_readings,
               COUNT(DISTINCT strftime('%Y-%m-%d %H', timestamp)) as distinct_hours,
               COUNT(DISTINCT date(timestamp)) as distinct_days,
               MIN(timestamp) as first_seen,
               MAX(timestamp) as last_seen
        FROM readings
        GROUP BY sensor_id
        HAVING distinct_hours > 1
        ORDER BY distinct_hours DESC, total_readings DESC
    """)
    repeats = cur.fetchall()

    if not repeats:
        print("No repeat visitors detected yet. Keep capturing!")
        return

    print(f"\nFound {len(repeats)} sensor(s) seen across multiple hours:\n")
    print(f"  {'Sensor ID':<14} {'Model':<30} {'Readings':>8} {'Hours':>6} {'Days':>5} {'First Seen':<20} {'Last Seen':<20}")
    print(f"  {'-'*14} {'-'*30} {'-'*8} {'-'*6} {'-'*5} {'-'*20} {'-'*20}")
    for sid, model, readings, hours, days, first, last in repeats:
        print(f"  {sid:<14} {model:<30} {readings:>8} {hours:>6} {days:>5} {first:<20} {last:<20}")

    # Privacy impact summary
    est_vehicles = len(repeats) // 4  # rough estimate
    print(f"\n  ~{max(1, est_vehicles)} vehicle(s) could be re-identified across time windows")
    print(f"  This demonstrates passive vehicle tracking via TPMS is feasible")


def hourly_distribution(conn):
    """Show when sensors are captured by hour of day."""
    print("\n" + "=" * 70)
    print("Hourly Distribution")
    print("=" * 70)

    cur = conn.execute("""
        SELECT strftime('%H', timestamp) as hour,
               COUNT(*) as readings,
               COUNT(DISTINCT sensor_id) as sensors
        FROM readings
        GROUP BY hour
        ORDER BY hour
    """)
    rows = cur.fetchall()
    if not rows:
        print("No data.")
        return

    max_sensors = max(r[2] for r in rows)
    print(f"\n  {'Hour':<6} {'Readings':>8} {'Sensors':>8}  Bar")
    print(f"  {'-'*6} {'-'*8} {'-'*8}  {'-'*40}")
    for hour, readings, sensors in rows:
        bar = "█" * int(40 * sensors / max_sensors) if max_sensors > 0 else ""
        print(f"  {hour}:00  {readings:>8} {sensors:>8}  {bar}")


def vehicle_groups(conn):
    """Show correlated vehicle groups from the vehicles table."""
    print("\n" + "=" * 70)
    print("Vehicle Groups (Correlated Sensor Sets)")
    print("=" * 70)

    cur = conn.execute("""
        SELECT vehicle_hash, sensor_ids, first_seen, last_seen, sighting_count
        FROM vehicles ORDER BY first_seen
    """)
    rows = cur.fetchall()

    if not rows:
        print("No vehicle groups yet. Run capture with Ctrl+C to trigger correlation.")
        return

    for i, (vhash, sensor_ids_json, first, last, sightings) in enumerate(rows, 1):
        sensor_ids = json.loads(sensor_ids_json)
        print(f"\n  Vehicle {i}: {len(sensor_ids)} sensor(s), seen {sightings}x")
        print(f"    First: {first}  Last: {last}")
        for sid in sensor_ids:
            # Get model for this sensor
            cur2 = conn.execute(
                "SELECT model FROM readings WHERE sensor_id = ? LIMIT 1", (sid,)
            )
            row = cur2.fetchone()
            model = row[0] if row else "unknown"
            print(f"    {sid} ({model})")


def export_csv(conn):
    """Export readings to CSV for further analysis."""
    csv_path = DB_PATH.parent / "tpms_readings.csv"
    cur = conn.execute("""
        SELECT timestamp, frequency_mhz, protocol, model, sensor_id,
               pressure_kpa, temperature_c, battery_ok, flags
        FROM readings ORDER BY timestamp
    """)

    with open(csv_path, "w") as f:
        f.write("timestamp,frequency_mhz,protocol,model,sensor_id,pressure_kpa,temperature_c,battery_ok,flags\n")
        for row in cur:
            f.write(",".join(str(v) if v is not None else "" for v in row) + "\n")

    print(f"\nExported to {csv_path}")


def stalking_risk_assessment(conn):
    """Assess the stalking risk based on captured data."""
    print("\n" + "=" * 70)
    print("Stalking Risk Assessment (for paper)")
    print("=" * 70)

    cur = conn.execute("SELECT COUNT(DISTINCT sensor_id) FROM readings")
    total_sensors = cur.fetchone()[0]

    cur = conn.execute("""
        SELECT COUNT(DISTINCT sensor_id) FROM (
            SELECT sensor_id,
                   COUNT(DISTINCT strftime('%Y-%m-%d %H', timestamp)) as hrs
            FROM readings GROUP BY sensor_id HAVING hrs > 1
        )
    """)
    reidentifiable = cur.fetchone()[0]

    cur = conn.execute("""
        SELECT sensor_id,
               julianday(MAX(timestamp)) - julianday(MIN(timestamp)) as span_days
        FROM readings
        GROUP BY sensor_id
        HAVING span_days > 0
        ORDER BY span_days DESC LIMIT 1
    """)
    row = cur.fetchone()
    longest_track = row[1] if row else 0

    print(f"""
  Equipment cost:         ~$50 (2x RTL-SDR dongles)
  Software:               Free (rtl_433, open source)
  Skill required:         Minimal (run a Python script)

  Sensors captured:       {total_sensors}
  Re-identifiable:        {reidentifiable} ({100*reidentifiable/max(total_sensors,1):.0f}%)
  Longest tracking span:  {longest_track:.1f} days

  RISK LEVEL: {"HIGH" if reidentifiable > 0 else "NEEDS MORE DATA"}

  Key findings for paper:
  - TPMS sensors broadcast unique IDs in the clear
  - No authentication or encryption on any observed protocol
  - Passive monitoring requires no interaction with the target vehicle
  - Cost of attack: under $50 in hardware + free software
  - A single monitoring station can observe all passing vehicles
  - Multiple stations could build movement profiles

  Mitigation recommendations:
  - TPMS sensors should use rolling IDs (like BLE privacy)
  - Frequency-hopping or spread-spectrum modulation
  - Reduced transmit power (current range often exceeds safety needs)
  - Regulatory bodies should mandate TPMS privacy standards
""")


def main():
    conn = get_conn()

    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "csv":
            export_csv(conn)
        elif cmd == "repeat":
            repeat_visitors(conn)
        elif cmd == "risk":
            stalking_risk_assessment(conn)
        elif cmd == "hourly":
            hourly_distribution(conn)
        elif cmd == "vehicles":
            vehicle_groups(conn)
        else:
            print(f"Unknown command: {cmd}")
            print("Usage: tpms_analyze.py [csv|repeat|risk|hourly|vehicles]")
    else:
        overview(conn)
        repeat_visitors(conn)
        hourly_distribution(conn)
        vehicle_groups(conn)
        stalking_risk_assessment(conn)

    conn.close()


if __name__ == "__main__":
    main()
