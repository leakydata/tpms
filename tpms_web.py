#!/usr/bin/env python3
"""
TPMS Web Dashboard
Real-time web interface for monitoring TPMS captures.
Reads from the same SQLite database as tpms_capture.py.
"""

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template, jsonify, request, Response

DB_PATH = Path(__file__).parent / "tpms_data.db"

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# ── Pages ────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/readings")
def readings_page():
    return render_template("readings.html")


@app.route("/sensors")
def sensors_page():
    return render_template("sensors.html")


@app.route("/signals")
def signals_page():
    return render_template("signals.html")


@app.route("/unknown")
def unknown_page():
    return render_template("unknown.html")


# ── API endpoints ────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    db = get_db()
    try:
        total_signals = db.execute("SELECT COUNT(*) FROM signals").fetchone()[0]
        total_readings = db.execute("SELECT COUNT(*) FROM readings").fetchone()[0]
        unique_sensors = db.execute("SELECT COUNT(*) FROM sensors").fetchone()[0]
        est_vehicles = max(1, unique_sensors // 4) if unique_sensors > 0 else 0

        first = db.execute("SELECT MIN(timestamp) FROM readings").fetchone()[0]
        last = db.execute("SELECT MAX(timestamp) FROM readings").fetchone()[0]

        # Signal type breakdown
        tpms_signals = db.execute("SELECT COUNT(*) FROM signals WHERE type='TPMS'").fetchone()[0]
        non_tpms_signals = total_signals - tpms_signals

        # Readings per band
        r315 = db.execute("SELECT COUNT(*) FROM readings WHERE frequency_mhz < 400").fetchone()[0]
        r433 = db.execute("SELECT COUNT(*) FROM readings WHERE frequency_mhz >= 400 OR frequency_mhz IS NULL").fetchone()[0]

        # Protocol breakdown
        protocols = db.execute("""
            SELECT model, COUNT(*) as cnt, COUNT(DISTINCT sensor_id) as sensors
            FROM readings GROUP BY model ORDER BY cnt DESC
        """).fetchall()

        # Unknown signals count
        unknown_tables = [r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='unknown_signals'"
        ).fetchall()]
        unknown_count = 0
        if "unknown_signals" in unknown_tables:
            unknown_count = db.execute("SELECT COUNT(*) FROM unknown_signals").fetchone()[0]

        # Re-identification metrics (for research)
        try:
            repeat_sensors = db.execute(
                "SELECT COUNT(*) FROM sensors WHERE sighting_count > 1"
            ).fetchone()[0]
            total_sightings = db.execute(
                "SELECT COALESCE(SUM(sighting_count), 0) FROM sensors"
            ).fetchone()[0]
        except Exception:
            repeat_sensors = 0
            total_sightings = 0

        # Average confidence of recent readings
        try:
            avg_conf_row = db.execute(
                "SELECT AVG(confidence) FROM readings WHERE confidence IS NOT NULL"
            ).fetchone()
            avg_confidence = avg_conf_row[0] if avg_conf_row and avg_conf_row[0] else None
        except Exception:
            avg_confidence = None

        # High-confidence vehicles (groups with 2+ tires)
        try:
            full_vehicles = db.execute(
                "SELECT COUNT(*) FROM vehicles WHERE json_array_length(sensor_ids) >= 2"
            ).fetchone()[0]
        except Exception:
            full_vehicles = 0

        return jsonify({
            "total_signals": total_signals,
            "total_readings": total_readings,
            "tpms_signals": tpms_signals,
            "non_tpms_signals": non_tpms_signals,
            "unique_sensors": unique_sensors,
            "est_vehicles": est_vehicles,
            "unknown_signals": unknown_count,
            "repeat_sensors": repeat_sensors,
            "total_sightings": total_sightings,
            "full_vehicles": full_vehicles,
            "avg_confidence": round(avg_confidence, 1) if avg_confidence else None,
            "first_reading": first,
            "last_reading": last,
            "readings_315": r315,
            "readings_433": r433,
            "protocols": [{"model": p["model"], "readings": p["cnt"], "sensors": p["sensors"]}
                          for p in protocols],
        })
    finally:
        db.close()


@app.route("/api/station")
def api_station():
    db = get_db()
    try:
        rows = db.execute("SELECT key, value FROM station").fetchall()
        station = {r["key"]: r["value"] for r in rows}
        return jsonify(station)
    except Exception:
        return jsonify({})
    finally:
        db.close()


@app.route("/api/receivers")
def api_receivers():
    db = get_db()
    try:
        # Check if receivers table exists
        tables = [r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='receivers'"
        ).fetchall()]
        if "receivers" not in tables:
            return jsonify({"receivers": [], "capture_running": False})

        rows = db.execute("SELECT * FROM receivers ORDER BY device_index").fetchall()
        receivers = []
        capture_running = False
        for r in rows:
            rec = dict(r)
            # Determine health based on heartbeat age
            if rec["last_heartbeat"]:
                try:
                    hb = datetime.fromisoformat(rec["last_heartbeat"])
                    age_secs = (datetime.now(timezone.utc) - hb.replace(tzinfo=timezone.utc)).total_seconds()
                    rec["heartbeat_age_secs"] = round(age_secs)
                    if rec["status"] == "running" and age_secs > 60:
                        rec["status"] = "stale"
                    if rec["status"] == "running":
                        capture_running = True
                except Exception:
                    rec["heartbeat_age_secs"] = None
            else:
                rec["heartbeat_age_secs"] = None
            receivers.append(rec)

        return jsonify({"receivers": receivers, "capture_running": capture_running})
    finally:
        db.close()


@app.route("/api/readings")
def api_readings():
    db = get_db()
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        model_filter = request.args.get("model", "")
        sensor_filter = request.args.get("sensor_id", "")
        offset = (page - 1) * per_page

        where_clauses = []
        params = []
        if model_filter:
            where_clauses.append("model LIKE ?")
            params.append(f"%{model_filter}%")
        if sensor_filter:
            where_clauses.append("sensor_id LIKE ?")
            params.append(f"%{sensor_filter}%")

        where = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        total = db.execute(f"SELECT COUNT(*) FROM readings {where}", params).fetchone()[0]
        rows = db.execute(
            f"SELECT * FROM readings {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()

        return jsonify({
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
            "readings": [dict(r) for r in rows],
        })
    finally:
        db.close()


@app.route("/api/sensors")
def api_sensors():
    db = get_db()
    try:
        rows = db.execute("""
            SELECT * FROM sensors ORDER BY last_seen DESC
        """).fetchall()
        return jsonify({"sensors": [dict(r) for r in rows]})
    finally:
        db.close()


@app.route("/api/signals")
def api_signals():
    db = get_db()
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        type_filter = request.args.get("type", "")
        offset = (page - 1) * per_page

        where = ""
        params = []
        if type_filter:
            where = "WHERE type = ?"
            params = [type_filter]

        total = db.execute(f"SELECT COUNT(*) FROM signals {where}", params).fetchone()[0]
        rows = db.execute(
            f"SELECT id, timestamp, frequency_mhz, frequency_label, protocol, model, type, sensor_id, rssi, snr, noise FROM signals {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()

        return jsonify({
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
            "signals": [dict(r) for r in rows],
        })
    finally:
        db.close()


@app.route("/api/vehicles")
def api_vehicles():
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM vehicles ORDER BY last_seen DESC").fetchall()
        vehicles = []
        for r in rows:
            v = dict(r)
            v["sensor_ids"] = json.loads(v["sensor_ids"])
            vehicles.append(v)
        return jsonify({"vehicles": vehicles})
    finally:
        db.close()


@app.route("/api/activity")
def api_activity():
    """Readings per minute for the last hour, for charting."""
    db = get_db()
    try:
        rows = db.execute("""
            SELECT strftime('%Y-%m-%d %H:%M', timestamp) as minute,
                   COUNT(*) as count,
                   COUNT(DISTINCT sensor_id) as sensors
            FROM readings
            WHERE timestamp >= datetime('now', '-1 hour')
            GROUP BY minute ORDER BY minute
        """).fetchall()
        return jsonify({"activity": [dict(r) for r in rows]})
    finally:
        db.close()


@app.route("/api/live")
def api_live():
    """Server-Sent Events stream of new readings."""
    def generate():
        db = get_db()
        last_id = db.execute("SELECT MAX(id) FROM readings").fetchone()[0] or 0
        db.close()

        while True:
            time.sleep(1)
            try:
                db = get_db()
                rows = db.execute(
                    "SELECT * FROM readings WHERE id > ? ORDER BY id", (last_id,)
                ).fetchall()
                db.close()

                for row in rows:
                    last_id = row["id"]
                    yield f"data: {json.dumps(dict(row))}\n\n"

                # Also send stats periodically
                if not rows:
                    db = get_db()
                    total = db.execute("SELECT COUNT(*) FROM readings").fetchone()[0]
                    sensors = db.execute("SELECT COUNT(*) FROM sensors").fetchone()[0]
                    signals = db.execute("SELECT COUNT(*) FROM signals").fetchone()[0]
                    db.close()
                    yield f"event: stats\ndata: {json.dumps({'total_readings': total, 'unique_sensors': sensors, 'total_signals': signals})}\n\n"
            except Exception:
                pass

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/unknown")
def api_unknown():
    db = get_db()
    try:
        # Check table exists first
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='unknown_signals'").fetchall()]
        if "unknown_signals" not in tables:
            return jsonify({"total": 0, "unknowns": [], "page": 1, "pages": 0})

        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        offset = (page - 1) * per_page
        total = db.execute("SELECT COUNT(*) FROM unknown_signals").fetchone()[0]
        rows = db.execute("SELECT * FROM unknown_signals ORDER BY timestamp DESC LIMIT ? OFFSET ?", (per_page, offset)).fetchall()
        return jsonify({
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
            "unknowns": [dict(r) for r in rows],
        })
    finally:
        db.close()


@app.route("/api/sensor/<sensor_id>")
def api_sensor_detail(sensor_id):
    db = get_db()
    try:
        sensor = db.execute("SELECT * FROM sensors WHERE sensor_id = ?", (sensor_id,)).fetchone()
        if not sensor:
            return jsonify({"error": "not found"}), 404
        readings = db.execute(
            "SELECT timestamp, pressure_kpa, temperature_c, battery_ok, flags FROM readings WHERE sensor_id = ? ORDER BY timestamp DESC LIMIT 200",
            (sensor_id,)
        ).fetchall()
        return jsonify({
            "sensor": dict(sensor),
            "readings": [dict(r) for r in readings],
        })
    finally:
        db.close()


@app.route("/api/export/readings")
def api_export_readings():
    db = get_db()
    try:
        rows = db.execute("SELECT timestamp, frequency_mhz, protocol, model, sensor_id, pressure_kpa, temperature_c, battery_ok, flags FROM readings ORDER BY timestamp").fetchall()
        def generate():
            yield "timestamp,frequency_mhz,protocol,model,sensor_id,pressure_kpa,temperature_c,battery_ok,flags\n"
            for r in rows:
                yield ",".join(str(v) if v is not None else "" for v in r) + "\n"
        return Response(generate(), mimetype="text/csv",
                       headers={"Content-Disposition": "attachment; filename=tpms_readings.csv"})
    finally:
        db.close()


@app.route("/api/export/sensors")
def api_export_sensors():
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM sensors ORDER BY last_seen DESC").fetchall()
        if not rows:
            return Response("", mimetype="text/csv",
                           headers={"Content-Disposition": "attachment; filename=tpms_sensors.csv"})
        columns = rows[0].keys()
        def generate():
            yield ",".join(columns) + "\n"
            for r in rows:
                yield ",".join(str(v) if v is not None else "" for v in r) + "\n"
        return Response(generate(), mimetype="text/csv",
                       headers={"Content-Disposition": "attachment; filename=tpms_sensors.csv"})
    finally:
        db.close()


def main():
    print(f"\n  TPMS Web Dashboard")
    print(f"  Database: {DB_PATH}")
    print(f"  Starting on http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)


if __name__ == "__main__":
    main()
