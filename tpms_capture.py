#!/usr/bin/env python3
"""
TPMS Sensor Capture Tool
Captures tire pressure monitoring system (TPMS) broadcasts from passing vehicles
using rtl_433 and RTL-SDR dongles (315 MHz + 433.92 MHz).

Stores ALL decoded signals for analysis, with TPMS-specific enrichment.
Supports any number of RTL-SDR dongles (use a powered USB hub).

For research on anti-stalking / vehicle tracking privacy.
"""

import json
import sqlite3
import subprocess
import signal
import shutil
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

DB_PATH = Path(__file__).parent / "tpms_data.db"

# Known TPMS protocol numbers in rtl_433.
TPMS_PROTOCOLS = {
    59, 60, 82, 88, 89, 90, 95, 110, 123, 140, 156, 168, 180, 186,
    201, 203, 208, 212, 225, 226, 241, 248, 252, 257, 275, 295, 298, 299,
}

# Protocols disabled by default in rtl_433 — we enable them all.
DISABLED_BY_DEFAULT = [
    6, 7, 13, 14, 24, 37, 48, 61, 62, 64, 72, 86, 101, 106, 107,
    117, 118, 123, 129, 150, 162, 169, 198, 200, 216, 233, 242, 245,
    248, 260, 270,
]

# Frequency presets for TPMS bands
FREQ_PRESETS = {
    "315MHz": 315_000_000,   # North America
    "433MHz": 433_920_000,   # Europe / aftermarket
}

# ── Logging helpers ──────────────────────────────────────────────────────────

COLORS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "white": "\033[37m",
}
if not sys.stdout.isatty():
    COLORS = {k: "" for k in COLORS}
C = COLORS

def _ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def log_info(msg):
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['cyan']}INFO{C['reset']}  {msg}", flush=True)
def log_ok(msg):
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['green']}  OK{C['reset']}  {msg}", flush=True)
def log_warn(msg):
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['yellow']}WARN{C['reset']}  {msg}", flush=True)
def log_error(msg):
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['red']}ERROR{C['reset']} {msg}", flush=True)
def log_rx(msg):
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['green']}  RX{C['reset']}  {msg}", flush=True)
def log_db(msg):
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['magenta']}  DB{C['reset']}  {msg}", flush=True)
def log_sdr(msg):
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['blue']} SDR{C['reset']}  {msg}", flush=True)
def log_stats(msg):
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['white']}{C['bold']}STAT{C['reset']}  {msg}", flush=True)


# ── Database ─────────────────────────────────────────────────────────────────

def init_db():
    log_db(f"Opening database: {DB_PATH}")
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    log_db("Set journal_mode=WAL")

    # All decoded signals (TPMS and non-TPMS)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS signals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            device_index INTEGER,
            frequency_mhz REAL,
            frequency_label TEXT,
            protocol INTEGER,
            model TEXT,
            type TEXT,
            sensor_id TEXT,
            rssi REAL,
            snr REAL,
            noise REAL,
            raw_json TEXT NOT NULL
        )
    """)

    # TPMS-specific readings (enriched subset of signals)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signal_id INTEGER REFERENCES signals(id),
            timestamp TEXT NOT NULL,
            frequency_mhz REAL,
            protocol TEXT,
            model TEXT,
            sensor_id TEXT,
            pressure_kpa REAL,
            temperature_c REAL,
            battery_ok INTEGER,
            flags TEXT,
            raw_json TEXT NOT NULL
        )
    """)

    # Per-sensor tracking
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sensors (
            sensor_id TEXT PRIMARY KEY,
            model TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            reading_count INTEGER DEFAULT 1,
            min_pressure_kpa REAL,
            max_pressure_kpa REAL,
            min_temperature_c REAL,
            max_temperature_c REAL,
            last_pressure_kpa REAL,
            last_temperature_c REAL,
            last_battery_ok INTEGER,
            last_rssi REAL,
            notes TEXT
        )
    """)

    # Vehicle groups
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_hash TEXT UNIQUE NOT NULL,
            sensor_ids TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            sighting_count INTEGER DEFAULT 1,
            notes TEXT
        )
    """)

    conn.execute("CREATE INDEX IF NOT EXISTS idx_signals_timestamp ON signals(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_signals_model ON signals(model)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_signals_sensor_id ON signals(sensor_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_readings_sensor_id ON readings(sensor_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_readings_timestamp ON readings(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vehicles_hash ON vehicles(vehicle_hash)")
    conn.commit()

    cur = conn.execute("SELECT COUNT(*) FROM signals")
    total_signals = cur.fetchone()[0]
    cur = conn.execute("SELECT COUNT(*) FROM readings")
    total_readings = cur.fetchone()[0]
    cur = conn.execute("SELECT COUNT(*) FROM sensors")
    total_sensors = cur.fetchone()[0]
    if total_signals > 0:
        log_db(f"Existing data: {total_signals} signals, {total_readings} TPMS readings, {total_sensors} sensors")
    else:
        log_db("Database initialized (empty — fresh start)")

    return conn


# ── Field extraction ─────────────────────────────────────────────────────────

def extract_sensor_fields(data: dict) -> dict:
    sensor_id = str(
        data.get("id") or data.get("ID") or data.get("sensor_id")
        or data.get("code") or data.get("address") or ""
    )

    pressure = data.get("pressure_kPa") or data.get("pressure_PSI") or data.get("pressure_bar") or None
    if pressure is not None:
        if "pressure_PSI" in data and "pressure_kPa" not in data:
            pressure = float(pressure) * 6.89476
        elif "pressure_bar" in data and "pressure_kPa" not in data:
            pressure = float(pressure) * 100.0
        else:
            pressure = float(pressure)

    temperature = data.get("temperature_C") or data.get("temperature_F")
    if temperature is not None:
        if "temperature_F" in data and "temperature_C" not in data:
            temperature = (float(temperature) - 32) * 5 / 9
        else:
            temperature = float(temperature)

    battery = data.get("battery_ok")
    if battery is not None:
        battery = int(battery)

    flags = data.get("flags") or data.get("state") or data.get("status")

    return {
        "sensor_id": sensor_id,
        "pressure_kpa": pressure,
        "temperature_c": temperature,
        "battery_ok": battery,
        "flags": str(flags) if flags is not None else None,
    }


def is_tpms(data: dict) -> bool:
    if data.get("type", "").upper() == "TPMS":
        return True
    model = data.get("model", "").lower()
    if any(kw in model for kw in ("tpms", "tire", "tyre", "schrader", "pmv-107",
                                   "steelmate", "jansite", "eez", "tyreguard")):
        return True
    proto = data.get("protocol")
    if proto is not None and int(proto) in TPMS_PROTOCOLS:
        return True
    if "pressure_kPa" in data or "pressure_PSI" in data or "pressure_bar" in data:
        if ("id" in data or "ID" in data) and "humidity" not in data:
            return True
    return False


def detect_dongles():
    """Auto-detect connected RTL-SDR dongles."""
    try:
        result = subprocess.run(
            ["rtl_test", "-t"], capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if line.strip().startswith("Found"):
                import re
                m = re.search(r"Found (\d+) device", line)
                if m:
                    return int(m.group(1))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return 0


# ── Main capture class ───────────────────────────────────────────────────────

class TPMSCapture:
    def __init__(self):
        self.conn = init_db()
        self.processes = []
        self.running = True
        self.lock = threading.Lock()
        self.stats = defaultdict(int)
        self.unique_sensors = set()
        self.sensor_models = {}
        self.start_time = datetime.now(timezone.utc)
        self.last_status_time = time.monotonic()
        self.stderr_threads = []
        self._decode_buffer = []
        self._decode_buffer_key = None
        self._decode_flush_timer = None

    def build_rtl433_cmd(self, device_index: int, frequency: int) -> list:
        protocol_args = []
        for p in DISABLED_BY_DEFAULT:
            protocol_args.extend(["-R", str(p)])
        return [
            "rtl_433",
            "-d", str(device_index),
            "-f", str(frequency),
            "-M", "time:utc",
            "-M", "protocol",
            "-M", "level",
            "-F", "json",
        ] + protocol_args

    def _stream_stderr(self, proc, freq_label: str):
        for line in proc.stderr:
            line = line.strip()
            if not line:
                continue
            lower = line.lower()
            if "if you want" in lower:
                log_sdr(f"[{freq_label}] {line}")
            elif "error" in lower or "fail" in lower:
                log_error(f"[{freq_label}] {line}")
            elif "pll not locked" in lower:
                log_warn(f"[{freq_label}] {line} (usually harmless at startup)")
            elif "warning" in lower or "warn" in lower:
                log_warn(f"[{freq_label}] {line}")
            else:
                log_sdr(f"[{freq_label}] {line}")

    def _score_decode(self, fields):
        score = 0
        temp = fields["temperature_c"]
        if temp is not None:
            score += 10 if -10 <= temp <= 80 else -20
        pres = fields["pressure_kpa"]
        if pres is not None:
            score += 5 if 100 <= pres <= 400 else -10
        return score

    def _flush_decode_buffer(self):
        if not self._decode_buffer:
            return
        buf = self._decode_buffer
        self._decode_buffer = []
        self._decode_buffer_key = None

        # Group by TPMS vs non-TPMS
        tpms_decodes = [(d, f, fl) for d, f, fl in buf if is_tpms(d)]
        non_tpms = [(d, f, fl) for d, f, fl in buf if not is_tpms(d)]

        # Store all non-TPMS signals
        for data, fields, freq_label in non_tpms:
            self._store_signal(data, freq_label)

        if len(tpms_decodes) == 0:
            pass
        elif len(tpms_decodes) == 1:
            self._commit_tpms(*tpms_decodes[0])
        else:
            scored = [(self._score_decode(f), d, f, fl) for d, f, fl in tpms_decodes]
            scored.sort(key=lambda x: x[0], reverse=True)
            _, best_data, best_fields, best_fl = scored[0]
            self._commit_tpms(best_data, best_fields, best_fl)
            suppressed = [s[1].get("model", "?") for s in scored[1:]]
            if suppressed:
                log_info(f"DEDUP: suppressed {len(suppressed)} duplicate(s): {', '.join(suppressed)}")

    def _store_signal(self, data, freq_label, device_index=None):
        """Store any decoded signal in the signals table."""
        timestamp = data.get("time", datetime.now(timezone.utc).isoformat())
        sensor_id = str(data.get("id") or data.get("ID") or data.get("sensor_id")
                        or data.get("code") or data.get("address") or "")
        with self.lock:
            self.conn.execute(
                """INSERT INTO signals
                   (timestamp, device_index, frequency_mhz, frequency_label,
                    protocol, model, type, sensor_id, rssi, snr, noise, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    timestamp, device_index, data.get("freq"),
                    freq_label, data.get("protocol"), data.get("model"),
                    data.get("type", ""), sensor_id,
                    data.get("rssi"), data.get("snr"), data.get("noise"),
                    json.dumps(data),
                ),
            )
            self.conn.commit()
            self.stats["total_signals"] += 1

    def _commit_tpms(self, data, fields, freq_label):
        """Store a TPMS decode in both signals and readings tables, update sensor."""
        timestamp = data.get("time", datetime.now(timezone.utc).isoformat())
        model = data.get("model", "unknown")
        protocol = data.get("protocol", "")
        freq_mhz = data.get("freq", None)
        rssi = data.get("rssi", None)
        snr = data.get("snr", None)
        noise = data.get("noise", None)
        sid = fields["sensor_id"]

        is_new = sid not in self.unique_sensors

        with self.lock:
            # Store in signals table
            cur = self.conn.execute(
                """INSERT INTO signals
                   (timestamp, frequency_mhz, frequency_label, protocol, model,
                    type, sensor_id, rssi, snr, noise, raw_json)
                   VALUES (?, ?, ?, ?, ?, 'TPMS', ?, ?, ?, ?, ?)""",
                (timestamp, freq_mhz, freq_label, protocol, model,
                 sid, rssi, snr, noise, json.dumps(data)),
            )
            signal_id = cur.lastrowid

            # Store in TPMS readings table
            self.conn.execute(
                """INSERT INTO readings
                   (signal_id, timestamp, frequency_mhz, protocol, model, sensor_id,
                    pressure_kpa, temperature_c, battery_ok, flags, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (signal_id, timestamp, freq_mhz, str(protocol), model, sid,
                 fields["pressure_kpa"], fields["temperature_c"],
                 fields["battery_ok"], fields["flags"], json.dumps(data)),
            )

            # Upsert sensor record
            self.conn.execute("""
                INSERT INTO sensors
                    (sensor_id, model, first_seen, last_seen, reading_count,
                     min_pressure_kpa, max_pressure_kpa, min_temperature_c, max_temperature_c,
                     last_pressure_kpa, last_temperature_c, last_battery_ok, last_rssi)
                VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sensor_id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    reading_count = reading_count + 1,
                    min_pressure_kpa = MIN(COALESCE(min_pressure_kpa, excluded.min_pressure_kpa), excluded.min_pressure_kpa),
                    max_pressure_kpa = MAX(COALESCE(max_pressure_kpa, excluded.max_pressure_kpa), excluded.max_pressure_kpa),
                    min_temperature_c = MIN(COALESCE(min_temperature_c, excluded.min_temperature_c), excluded.min_temperature_c),
                    max_temperature_c = MAX(COALESCE(max_temperature_c, excluded.max_temperature_c), excluded.max_temperature_c),
                    last_pressure_kpa = COALESCE(excluded.last_pressure_kpa, last_pressure_kpa),
                    last_temperature_c = COALESCE(excluded.last_temperature_c, last_temperature_c),
                    last_battery_ok = COALESCE(excluded.last_battery_ok, last_battery_ok),
                    last_rssi = COALESCE(excluded.last_rssi, last_rssi)
            """, (sid, model, timestamp, timestamp,
                  fields["pressure_kpa"], fields["pressure_kpa"],
                  fields["temperature_c"], fields["temperature_c"],
                  fields["pressure_kpa"], fields["temperature_c"],
                  fields["battery_ok"], rssi))

            self.conn.commit()

            self.stats["total_signals"] += 1
            self.stats["total_readings"] += 1
            self.stats[f"readings_{freq_label}"] += 1
            self.unique_sensors.add(sid)
            self.stats["unique_sensors"] = len(self.unique_sensors)
            self.sensor_models[sid] = model

        # Build log line
        parts = [f"[{freq_label}] {C['bold']}{model}{C['reset']}  id={C['cyan']}{sid}{C['reset']}"]
        if fields["pressure_kpa"]:
            parts.append(f"pressure={fields['pressure_kpa']:.1f}kPa ({fields['pressure_kpa']/6.89476:.1f}psi)")
        if fields["temperature_c"] is not None:
            parts.append(f"temp={fields['temperature_c']:.1f}C")
        if fields["battery_ok"] is not None:
            parts.append(f"batt={'OK' if fields['battery_ok'] else 'LOW'}")
        if fields["flags"]:
            parts.append(f"flags={fields['flags']}")
        if rssi is not None:
            parts.append(f"RSSI={rssi:+.1f}dB")
        if snr is not None:
            parts.append(f"SNR={snr:.1f}dB")
        if noise is not None:
            parts.append(f"noise={noise:+.1f}dB")
        if freq_mhz:
            parts.append(f"freq={freq_mhz:.3f}MHz")
        parts.append(f"proto={protocol}")

        new_tag = f"  {C['yellow']}** NEW SENSOR **{C['reset']}" if is_new else ""
        log_rx("  ".join(parts) + new_tag)

        if is_new:
            log_db(f"New sensor {sid} ({model}) — {self.stats['unique_sensors']} unique total")

    def process_line(self, line: str, freq_label: str):
        line = line.strip()
        if not line:
            return
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            log_warn(f"[{freq_label}] Non-JSON output: {line[:120]}")
            return

        model = data.get("model", "unknown")
        is_tpms_signal = is_tpms(data)

        if not is_tpms_signal:
            # Still store non-TPMS signals
            self._store_signal(data, freq_label)
            self.stats["non_tpms_signals"] += 1
            # Log occasionally (not every single one to avoid spam)
            if self.stats["non_tpms_signals"] % 100 == 1:
                log_info(f"[{freq_label}] Non-TPMS signal: model={model} (total non-TPMS: {self.stats['non_tpms_signals']})")
            return

        fields = extract_sensor_fields(data)
        rssi = data.get("rssi", None)
        timestamp = data.get("time", "")
        burst_key = (timestamp, rssi)

        if self._decode_buffer_key is not None and burst_key != self._decode_buffer_key:
            self._flush_decode_buffer()

        self._decode_buffer_key = burst_key
        self._decode_buffer.append((data, fields, freq_label))

        if self._decode_flush_timer is not None:
            self._decode_flush_timer.cancel()
        self._decode_flush_timer = threading.Timer(0.1, self._flush_decode_buffer)
        self._decode_flush_timer.daemon = True
        self._decode_flush_timer.start()

    def run_receiver(self, device_index: int, frequency: int, freq_label: str):
        cmd = self.build_rtl433_cmd(device_index, frequency)
        log_sdr(f"[{freq_label}] Launching rtl_433 on device {device_index}")
        log_sdr(f"[{freq_label}] Command: {' '.join(cmd)}")

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
        except FileNotFoundError:
            log_error(f"[{freq_label}] rtl_433 not found!")
            return
        except Exception as e:
            log_error(f"[{freq_label}] Failed to start rtl_433: {e}")
            return

        self.processes.append(proc)
        log_ok(f"[{freq_label}] rtl_433 started (PID {proc.pid})")

        stderr_t = threading.Thread(
            target=self._stream_stderr, args=(proc, freq_label), daemon=True,
        )
        stderr_t.start()
        self.stderr_threads.append(stderr_t)
        log_info(f"[{freq_label}] Listening for signals...")

        while self.running:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    if proc.returncode != 0 and self.running:
                        log_error(f"[{freq_label}] rtl_433 exited with code {proc.returncode}")
                    break
                continue
            self.process_line(line, freq_label)

        if self.running:
            log_warn(f"[{freq_label}] Receiver stopped unexpectedly")

    def print_periodic_status(self):
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        alive = sum(1 for p in self.processes if p.poll() is None)
        total_receivers = len(self.processes)
        r315 = self.stats.get("readings_315MHz", 0)
        r433 = self.stats.get("readings_433MHz", 0)
        est_v = max(1, self.stats["unique_sensors"] // 4) if self.stats["unique_sensors"] > 0 else 0

        log_stats(
            f"uptime={mins:02d}:{secs:02d}  "
            f"receivers={alive}/{total_receivers}  "
            f"signals={self.stats.get('total_signals', 0)}  "
            f"tpms_readings={self.stats['total_readings']} (315:{r315} 433:{r433})  "
            f"non_tpms={self.stats.get('non_tpms_signals', 0)}  "
            f"sensors={self.stats['unique_sensors']}  "
            f"est_vehicles=~{est_v}"
        )

    def correlate_vehicles(self):
        log_info("Correlating sensors into vehicle groups...")
        cur = self.conn.execute("""
            SELECT sensor_id, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
                   COUNT(*) as reading_count, model
            FROM readings GROUP BY sensor_id ORDER BY first_seen
        """)
        sensors = cur.fetchall()
        if not sensors:
            log_warn("No sensors captured — nothing to correlate")
            return

        groups, current_group, current_time = [], [], None
        for sid, first_seen, last_seen, count, model in sensors:
            t = datetime.fromisoformat(first_seen)
            if current_time is None or (t - current_time).total_seconds() < 30:
                current_group.append((sid, first_seen, last_seen, count, model))
                if current_time is None:
                    current_time = t
            else:
                if current_group:
                    groups.append(current_group)
                current_group = [(sid, first_seen, last_seen, count, model)]
                current_time = t
        if current_group:
            groups.append(current_group)

        for group in groups:
            sensor_ids = sorted(set(s[0] for s in group))
            vehicle_hash = "|".join(sensor_ids)
            first_seen = min(s[1] for s in group)
            last_seen = max(s[2] for s in group)
            self.conn.execute("""
                INSERT INTO vehicles (vehicle_hash, sensor_ids, first_seen, last_seen, sighting_count)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(vehicle_hash) DO UPDATE SET
                    last_seen = excluded.last_seen, sighting_count = sighting_count + 1
            """, (vehicle_hash, json.dumps(sensor_ids), first_seen, last_seen))
        self.conn.commit()
        log_ok(f"Correlated into {len(groups)} potential vehicle group(s)")

        for i, group in enumerate(groups, 1):
            sensor_ids = sorted(set(s[0] for s in group))
            models = set(s[4] for s in group)
            log_info(f"  Vehicle {i}: {len(sensor_ids)} sensor(s) — {', '.join(models)}")
            for sid in sensor_ids:
                log_info(f"    Sensor ID: {sid}")

    def print_summary(self):
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        mins, secs = int(elapsed // 60), int(elapsed % 60)
        est = max(1, self.stats['unique_sensors'] // 4) if self.stats['unique_sensors'] > 0 else 0

        print(f"\n{C['bold']}{'='*70}{C['reset']}")
        print(f"{C['bold']}  TPMS Capture Session Summary{C['reset']}")
        print(f"{C['bold']}{'='*70}{C['reset']}")
        print(f"  Duration:           {mins}m {secs}s")
        print(f"  Total signals:      {self.stats.get('total_signals', 0)}")
        print(f"  TPMS readings:      {self.stats['total_readings']}")
        print(f"  Non-TPMS signals:   {self.stats.get('non_tpms_signals', 0)}")
        print(f"  Unique TPMS sensors:{self.stats['unique_sensors']}")
        print(f"  Est. vehicles:      ~{est}")
        print(f"  315 MHz readings:   {self.stats.get('readings_315MHz', 0)}")
        print(f"  433 MHz readings:   {self.stats.get('readings_433MHz', 0)}")
        print(f"  Database:           {DB_PATH}")

        if self.sensor_models:
            model_counts = defaultdict(int)
            for model in self.sensor_models.values():
                model_counts[model] += 1
            print(f"\n  {C['bold']}Sensors by protocol:{C['reset']}")
            for model, count in sorted(model_counts.items(), key=lambda x: -x[1]):
                print(f"    {model:<35} {count} sensor(s)")
        print(f"{C['bold']}{'='*70}{C['reset']}\n")
        self.correlate_vehicles()

    def shutdown(self, signum=None, frame=None):
        if not self.running:
            return
        print()
        log_info("Shutdown signal received")
        self.running = False
        self._flush_decode_buffer()

        for proc in self.processes:
            if proc.poll() is None:
                log_info(f"Terminating rtl_433 PID {proc.pid}...")
                proc.terminate()
        for proc in self.processes:
            try:
                proc.wait(timeout=5)
                log_ok(f"rtl_433 PID {proc.pid} stopped")
            except subprocess.TimeoutExpired:
                log_warn(f"rtl_433 PID {proc.pid} didn't stop — killing")
                proc.kill()

        self.print_summary()
        self.conn.close()
        log_ok("Database closed. Goodbye!")
        sys.exit(0)

    def _check_prerequisites(self):
        log_info("Checking prerequisites...")
        rtl_path = shutil.which("rtl_433")
        if not rtl_path:
            log_error("rtl_433 not found in PATH!")
            return False
        log_ok(f"rtl_433 found: {rtl_path}")

        try:
            ver = subprocess.run(["rtl_433", "-V"], capture_output=True, text=True, timeout=5)
            log_ok(f"rtl_433 version: {(ver.stdout + ver.stderr).strip().split(chr(10))[0]}")
        except Exception:
            log_warn("Could not determine rtl_433 version")

        return True

    def run(self):
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

        print(f"\n{C['bold']}{C['cyan']}╔══════════════════════════════════════════════════════════════╗{C['reset']}")
        print(f"{C['bold']}{C['cyan']}║      TPMS Capture Tool — Anti-Stalking Research             ║{C['reset']}")
        print(f"{C['bold']}{C['cyan']}╚══════════════════════════════════════════════════════════════╝{C['reset']}\n")

        if not self._check_prerequisites():
            log_error("Prerequisites not met — exiting")
            sys.exit(1)

        # Auto-detect dongles
        n_dongles = detect_dongles()
        if n_dongles == 0:
            log_warn("No RTL-SDR devices detected — will try to start anyway")
            n_dongles = 2  # try the default 2

        log_ok(f"Detected {n_dongles} RTL-SDR dongle(s)")

        # Assign frequencies: cycle through bands
        freq_list = list(FREQ_PRESETS.items())
        assignments = []
        for i in range(n_dongles):
            label, freq = freq_list[i % len(freq_list)]
            if n_dongles > len(freq_list) and i >= len(freq_list):
                label = f"{label}-{i}"
            assignments.append((i, freq, label))

        print()
        log_info(f"Database: {DB_PATH}")
        log_info(f"All {317} protocols enabled (all signals stored, TPMS enriched)")
        for dev_idx, freq, label in assignments:
            log_info(f"Device {dev_idx}: {freq/1e6:.3f} MHz ({label})")
        log_info(f"Web dashboard: uv run tpms-web")
        log_info(f"Press Ctrl+C to stop and see summary")
        print()

        # Start receivers
        for dev_idx, freq, label in assignments:
            t = threading.Thread(
                target=self.run_receiver, args=(dev_idx, freq, label),
                daemon=True, name=f"receiver-{label}",
            )
            t.start()
            log_ok(f"{label} receiver thread started (device {dev_idx})")
        print()

        try:
            while self.running:
                time.sleep(1)
                now = time.monotonic()
                if now - self.last_status_time >= 30:
                    self.print_periodic_status()
                    self.last_status_time = now
                    for proc in self.processes:
                        if proc.poll() is not None and self.running:
                            log_warn(f"rtl_433 PID {proc.pid} has exited (code {proc.returncode})")
        except KeyboardInterrupt:
            self.shutdown()


def main():
    TPMSCapture().run()


if __name__ == "__main__":
    main()
