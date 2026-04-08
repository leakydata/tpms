#!/usr/bin/env python3
"""
TPMS Sensor Capture Tool
Captures tire pressure monitoring system (TPMS) broadcasts from passing vehicles
using rtl_433 and RTL-SDR dongles (315 MHz + 433.92 MHz).

Stores ALL decoded signals for analysis, with TPMS-specific enrichment.
Supports any number of RTL-SDR dongles (use a powered USB hub).

For research on anti-stalking / vehicle tracking privacy.
"""

import hashlib
import json
import re
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

# Default station location (used when no GPS dongle is present)
DEFAULT_LAT = 40.224619417522824
DEFAULT_LON = -77.2428142810988

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

# Serial-to-frequency mapping. If a dongle has a known serial, assign
# it to a specific frequency. Overrides tuner-based auto-assignment.
SERIAL_FREQ_MAP = {
    "TPMS_R820T": ("433MHz", 433_920_000),   # better tuner → primary band
    "TPMS_E4000": ("315MHz", 315_000_000),   # older tuner → secondary band
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

    # Station metadata (fixed GPS, or updated by USB GPS)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS station (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # Receiver / dongle status (written by capture, read by web dashboard)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS receivers (
            device_index INTEGER PRIMARY KEY,
            frequency_label TEXT NOT NULL,
            frequency_hz INTEGER NOT NULL,
            tuner TEXT,
            serial TEXT,
            pid INTEGER,
            status TEXT NOT NULL DEFAULT 'starting',
            started_at TEXT,
            last_heartbeat TEXT,
            last_signal_at TEXT,
            signals_count INTEGER DEFAULT 0,
            tpms_count INTEGER DEFAULT 0,
            last_error TEXT
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

    # Unknown / unrecognized signal detections with fingerprinting
    conn.execute("""
        CREATE TABLE IF NOT EXISTS unknown_signals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            device_index INTEGER,
            frequency_label TEXT,
            pulse_count INTEGER,
            width_ms REAL,
            modulation TEXT,
            raw_hex TEXT,
            triq_url TEXT,
            fingerprint TEXT,
            analysis_text TEXT,
            iq_filename TEXT,
            rssi REAL,
            noise REAL
        )
    """)

    # ── Auto-migrate: add columns that may be missing from older databases ──
    # SQLite doesn't error on duplicate ALTER ADD, so we catch and ignore.
    migrations = [
        "ALTER TABLE readings ADD COLUMN signal_id INTEGER REFERENCES signals(id)",
        "ALTER TABLE unknown_signals ADD COLUMN pulse_count INTEGER",
        "ALTER TABLE unknown_signals ADD COLUMN width_ms REAL",
        "ALTER TABLE unknown_signals ADD COLUMN modulation TEXT",
        "ALTER TABLE unknown_signals ADD COLUMN raw_hex TEXT",
        "ALTER TABLE unknown_signals ADD COLUMN fingerprint TEXT",
        "ALTER TABLE unknown_signals ADD COLUMN triq_url TEXT",
        "ALTER TABLE unknown_signals ADD COLUMN iq_filename TEXT",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
            log_db(f"Migration applied: {sql.strip()[:60]}...")
        except sqlite3.OperationalError:
            pass  # column already exists

    # Set default station location if not already set
    conn.execute("INSERT OR IGNORE INTO station (key, value) VALUES ('lat', ?)", (str(DEFAULT_LAT),))
    conn.execute("INSERT OR IGNORE INTO station (key, value) VALUES ('lon', ?)", (str(DEFAULT_LON),))

    conn.execute("CREATE INDEX IF NOT EXISTS idx_signals_timestamp ON signals(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_signals_model ON signals(model)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_signals_sensor_id ON signals(sensor_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_readings_sensor_id ON readings(sensor_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_readings_timestamp ON readings(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vehicles_hash ON vehicles(vehicle_hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_unknown_timestamp ON unknown_signals(timestamp)")
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
    """Auto-detect connected RTL-SDR dongles and identify their tuners.

    Returns a list of dicts: [{"index": 0, "tuner": "R820T", "name": "..."}, ...]
    Uses rtl_433 -T 0 to probe each device briefly and read the tuner type.
    """
    # First find how many devices
    n_devices = 0
    try:
        result = subprocess.run(
            ["rtl_test", "-t"], capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if line.strip().startswith("Found"):
                m = re.search(r"Found (\d+) device", line)
                if m:
                    n_devices = int(m.group(1))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if n_devices == 0:
        return []

    # Probe each device to find its tuner type and serial
    dongles = []
    for i in range(n_devices):
        tuner = "unknown"
        serial = ""
        try:
            # Read EEPROM for serial
            result = subprocess.run(
                ["rtl_eeprom", "-d", str(i)],
                capture_output=True, text=True, timeout=5
            )
            for line in (result.stdout + result.stderr).split("\n"):
                if "Serial number:" in line and "enabled" not in line:
                    serial = line.split(":")[-1].strip()
                if "Found" in line and "tuner" in line.lower():
                    tuner = line.split("Found ")[-1].strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: probe tuner with rtl_433 if rtl_eeprom didn't find it
        if tuner == "unknown":
            try:
                result = subprocess.run(
                    ["rtl_433", "-d", str(i), "-T", "0"],
                    capture_output=True, text=True, timeout=5
                )
                for line in (result.stdout + result.stderr).split("\n"):
                    if "Found" in line and "tuner" in line.lower():
                        tuner = line.split("Found ")[-1].strip()
                        break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        dongles.append({"index": i, "tuner": tuner, "serial": serial})
        log_sdr(f"Device {i}: {tuner}  serial={serial or 'none'}")

    return dongles


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
        self._receiver_info = {}  # device_index -> {label, freq, pid, status, ...}
        self._analysis_buffer = {}  # device_index -> list of lines

    def build_rtl433_cmd(self, device_index: int, frequency: int) -> list:
        protocol_args = []
        for p in DISABLED_BY_DEFAULT:
            protocol_args.extend(["-R", str(p)])

        cmd = [
            "rtl_433",
            "-d", str(device_index),
            "-f", str(frequency),
            "-M", "time:utc",
            "-M", "protocol",
            "-M", "level",
            "-A",                                    # pulse analysis on unknown signals
            "-Y", "autolevel",                       # auto signal level detection
            "-Y", "minlevel=-15",                    # filter out weak noise, keep real signals
            "-F", "json",
        ] + protocol_args

        # Load custom flex decoders
        flex_dir = Path(__file__).parent / "flex_decoders"
        if flex_dir.is_dir():
            for conf in sorted(flex_dir.glob("*.conf")):
                cmd.extend(["-c", str(conf)])

        return cmd

    # Lines that are part of an -A pulse analysis block
    _ANALYSIS_PATTERNS = (
        "analyzing pulses", "total count:", "pulse width distribution",
        "gap width distribution", "pulse+gap period", "guessing modulation",
        "pulse_demod_", "bitbuffer", "codes :", "view at https://triq.org",
        "[00]", "[01]", "[02]", "[03]", "[04]",  # bitbuffer row indices
        "  [", "count:", "width:", "mean:", "min:", "max:",
    )

    def _is_analysis_line(self, lower_line):
        """Check if a stderr line is part of a pulse analysis block."""
        return any(p in lower_line for p in self._ANALYSIS_PATTERNS)

    def _stream_stderr(self, proc, freq_label: str, device_index: int):
        for line in proc.stderr:
            line = line.strip()
            if not line:
                # Blank line inside analysis block = still part of block
                if device_index in self._analysis_buffer:
                    self._analysis_buffer[device_index].append("")
                continue
            lower = line.lower()

            # Detect pulse analysis blocks from -A flag (unknown signals)
            if line.startswith("Analyzing pulses") and device_index not in self._analysis_buffer:
                # Start of new analysis block — buffer silently
                self._analysis_buffer[device_index] = [line]
                continue
            elif device_index in self._analysis_buffer:
                if self._is_analysis_line(lower):
                    self._analysis_buffer[device_index].append(line)
                    continue
                else:
                    # End of analysis block — check pulse count before storing
                    buf = self._analysis_buffer.pop(device_index)
                    # Quick check: extract pulse count from the 2nd line
                    store = True
                    if len(buf) >= 2:
                        m = re.search(r"Total count:\s*(\d+)", buf[1])
                        if m and int(m.group(1)) < 30:
                            self.stats["unknown_filtered"] += 1
                            store = False
                    if store:
                        self._store_unknown(device_index, freq_label, buf)
                    # Fall through to classify this line normally

            # Capture tuner info for receiver status
            if "found" in lower and "tuner" in lower:
                tuner = line.split("Found ")[-1].strip() if "Found " in line else line
                self._update_receiver(device_index, tuner=tuner)

            if "if you want" in lower:
                log_sdr(f"[{freq_label}] {line}")
            elif "error" in lower or "fail" in lower:
                log_error(f"[{freq_label}] {line}")
                self._update_receiver(device_index, last_error=line)
            elif "pll not locked" in lower:
                log_warn(f"[{freq_label}] {line} (usually harmless at startup)")
            elif "warning" in lower or "warn" in lower:
                log_warn(f"[{freq_label}] {line}")
            else:
                log_sdr(f"[{freq_label}] {line}")

    def _store_unknown(self, device_index, freq_label, lines):
        """Parse and store an unknown signal analysis block.

        Extracts structural features for fingerprinting:
        - Pulse count and width (protocol-level, stable across transmissions)
        - Modulation type (OOK, FSK, etc.)
        - Raw hex data (contains the actual bits — ID portion is stable)

        The fingerprint is a hash of the structural features (modulation +
        pulse count + timing), NOT the data payload. This means all sensors
        using the same protocol produce the same fingerprint. To identify
        individual sensors within an unknown protocol, compare the raw_hex
        across multiple receptions — the bits that stay constant are the ID.
        """
        now = datetime.now(timezone.utc).isoformat()
        analysis_text = "\n".join(lines)

        # Quick pre-filter: skip signals that aren't TPMS candidates.
        # Real TPMS signals have 30-120 pulses in 5-25ms.
        # Anything under 30 pulses is local device noise (garage doors,
        # security sensors, weather stations, etc.)
        for line in lines:
            m = re.search(r"Total count:\s*(\d+),\s*width:\s*([\d.]+)\s*ms", line)
            if m:
                pc = int(m.group(1))
                wms = float(m.group(2))
                if pc < 30:
                    self.stats["unknown_filtered"] += 1
                    return
                break

        # Extract fields
        pulse_count = None
        width_ms = None
        modulation = None
        raw_hex_parts = []
        triq_urls = []
        bitbuffer_rows = []    # complete bitbuffer data for future ID extraction
        pulse_widths = []      # pulse distribution for structural matching
        gap_widths = []        # gap distribution for structural matching

        for line in lines:
            # "Total count:   60,  width: 7.98 ms"
            m = re.search(r"Total count:\s*(\d+),\s*width:\s*([\d.]+)\s*ms", line)
            if m:
                pulse_count = int(m.group(1))
                width_ms = float(m.group(2))

            # Pulse/gap width distributions "[  0] count:  30, width:  52 us"
            m_dist = re.search(r"count:\s*(\d+),\s*width:\s*(\d+)\s*us", line)
            if m_dist:
                # Collect distribution data for fingerprinting
                pass  # already in analysis_text

            # "Guessing modulation: FSK_PCM" or "pulse_demod_pcm"
            if "guessing modulation:" in line.lower():
                modulation = line.split(":")[-1].strip()
            elif "pulse_demod_" in line.lower():
                m2 = re.search(r"pulse_demod_(\w+)", line.lower())
                if m2 and not modulation:
                    modulation = m2.group(1).upper()

            # triq.org visualization URLs (full URL for one-click analysis)
            if "triq.org/pdv/#" in line:
                url_start = line.index("https://triq.org")
                triq_urls.append(line[url_start:].strip())
                hex_part = line.split("#")[-1].strip()
                if hex_part:
                    raw_hex_parts.append(hex_part)

            # Bitbuffer rows like "[00] {68} ab cd ef ..."
            m3 = re.match(r"\s*\[(\d+)\]\s*\{(\d+)\}\s+([\da-fA-F\s]+)", line)
            if m3:
                row_idx = int(m3.group(1))
                bit_len = int(m3.group(2))
                hex_data = m3.group(3).strip()
                bitbuffer_rows.append(f"[{row_idx:02d}]{{{bit_len}}} {hex_data}")
                raw_hex_parts.append(hex_data)

        # Combine all hex data — keep bitbuffer rows separate with || delimiter
        # so they can be compared across captures for ID extraction
        if bitbuffer_rows:
            raw_hex = " || ".join(bitbuffer_rows)
        elif raw_hex_parts:
            raw_hex = " | ".join(raw_hex_parts)
        else:
            raw_hex = None

        triq_url = triq_urls[0] if triq_urls else None

        # Structural fingerprint: hash of protocol-level features
        # Uses bucketed values to group signals from the same protocol despite
        # minor timing variations between transmissions.
        # Pulse count bucketed to nearest 5, width to nearest 1ms,
        # ms-per-pulse ratio to nearest 0.05ms (the fundamental timing unit).
        if pulse_count and width_ms and pulse_count > 0:
            ms_per_pulse = round(width_ms / pulse_count * 20) / 20  # nearest 0.05
            pc_bucket = round(pulse_count / 5) * 5  # nearest 5
            w_bucket = round(width_ms)  # nearest 1ms
            fp_input = f"{modulation or '?'}:{pc_bucket}:{w_bucket}:{ms_per_pulse}"
        else:
            fp_input = f"{modulation or '?'}:{pulse_count or '?'}:{width_ms or '?'}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()[:16]

        with self.lock:
            self.conn.execute(
                """INSERT INTO unknown_signals
                   (timestamp, device_index, frequency_label, pulse_count,
                    width_ms, modulation, raw_hex, triq_url, fingerprint,
                    analysis_text)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (now, device_index, freq_label, pulse_count,
                 width_ms, modulation, raw_hex, triq_url, fingerprint,
                 analysis_text),
            )
            self.conn.commit()
            self.stats["unknown_signals"] += 1

        # Log summary
        mod_str = modulation or "unknown"
        pc_str = f"{pulse_count}p" if pulse_count else "?"
        w_str = f"{width_ms:.1f}ms" if width_ms else "?"
        hex_preview = (raw_hex[:50] + "...") if raw_hex and len(raw_hex) > 50 else (raw_hex or "no data")
        log_info(
            f"[{freq_label}] {C['yellow']}UNKNOWN{C['reset']}  "
            f"fp={C['cyan']}{fingerprint}{C['reset']}  "
            f"{mod_str} {pc_str} {w_str}  "
            f"hex={hex_preview}  "
            f"triq={'yes' if triq_url else 'no'}  "
            f"({len(lines)} lines)"
        )

    def _register_receiver(self, device_index, freq_label, frequency, pid):
        """Register a receiver in the database."""
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            self.conn.execute("""
                INSERT INTO receivers (device_index, frequency_label, frequency_hz, pid, status, started_at, last_heartbeat)
                VALUES (?, ?, ?, ?, 'starting', ?, ?)
                ON CONFLICT(device_index) DO UPDATE SET
                    frequency_label = excluded.frequency_label,
                    frequency_hz = excluded.frequency_hz,
                    pid = excluded.pid,
                    status = 'starting',
                    started_at = excluded.started_at,
                    last_heartbeat = excluded.last_heartbeat,
                    signals_count = 0,
                    tpms_count = 0,
                    last_error = NULL,
                    tuner = NULL,
                    serial = NULL
            """, (device_index, freq_label, frequency, pid, now, now))
            self.conn.commit()
        self._receiver_info[device_index] = {
            "label": freq_label, "freq": frequency, "pid": pid,
            "signals": 0, "tpms": 0,
        }

    def _update_receiver(self, device_index, status=None, tuner=None,
                         last_error=None, signal_received=False, tpms_received=False):
        """Update receiver status in the database."""
        now = datetime.now(timezone.utc).isoformat()
        sets = ["last_heartbeat = ?"]
        params = [now]

        if status:
            sets.append("status = ?")
            params.append(status)
        if tuner:
            sets.append("tuner = ?")
            params.append(tuner)
        if last_error:
            sets.append("last_error = ?")
            params.append(last_error)
        if signal_received:
            sets.append("signals_count = signals_count + 1")
            sets.append("last_signal_at = ?")
            params.append(now)
        if tpms_received:
            sets.append("tpms_count = tpms_count + 1")

        with self.lock:
            self.conn.execute(
                f"UPDATE receivers SET {', '.join(sets)} WHERE device_index = ?",
                params + [device_index],
            )
            self.conn.commit()

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

        # Filter out obvious false decodes (absurd temperature)
        tpms_decodes = [
            (d, f, fl) for d, f, fl in tpms_decodes
            if f["temperature_c"] is None or -20 <= f["temperature_c"] <= 80
        ]

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

    def _freq_label_to_device(self, freq_label):
        """Resolve a freq_label back to a device_index."""
        for idx, info in self._receiver_info.items():
            if info["label"] == freq_label:
                return idx
        return None

    def _store_signal(self, data, freq_label, device_index=None):
        """Store any decoded signal in the signals table."""
        timestamp = data.get("time", datetime.now(timezone.utc).isoformat())
        sensor_id = str(data.get("id") or data.get("ID") or data.get("sensor_id")
                        or data.get("code") or data.get("address") or "")
        if device_index is None:
            device_index = self._freq_label_to_device(freq_label)
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
        if device_index is not None:
            self._update_receiver(device_index, signal_received=True)

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

        dev_idx = self._freq_label_to_device(freq_label)
        if dev_idx is not None:
            self._update_receiver(dev_idx, signal_received=True, tpms_received=True)

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
            self._register_receiver(device_index, freq_label, frequency, 0)
            self._update_receiver(device_index, status="error", last_error="rtl_433 not found")
            return
        except Exception as e:
            log_error(f"[{freq_label}] Failed to start rtl_433: {e}")
            self._register_receiver(device_index, freq_label, frequency, 0)
            self._update_receiver(device_index, status="error", last_error=str(e))
            return

        self.processes.append(proc)
        self._register_receiver(device_index, freq_label, frequency, proc.pid)
        log_ok(f"[{freq_label}] rtl_433 started (PID {proc.pid})")

        stderr_t = threading.Thread(
            target=self._stream_stderr, args=(proc, freq_label, device_index),
            daemon=True,
        )
        stderr_t.start()
        self.stderr_threads.append(stderr_t)
        log_info(f"[{freq_label}] Listening for signals...")

        # Mark as running once we start reading
        self._update_receiver(device_index, status="running")

        while self.running:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    exit_code = proc.returncode
                    if exit_code != 0 and self.running:
                        log_error(f"[{freq_label}] rtl_433 exited with code {exit_code}")
                        self._update_receiver(device_index, status="error",
                                              last_error=f"exited with code {exit_code}")
                    else:
                        self._update_receiver(device_index, status="stopped")
                    break
                continue
            self.process_line(line, freq_label)

        if self.running:
            log_warn(f"[{freq_label}] Receiver stopped unexpectedly")
            self._update_receiver(device_index, status="error",
                                  last_error="stopped unexpectedly")

    def print_periodic_status(self):
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        alive = sum(1 for p in self.processes if p.poll() is None)
        total_receivers = len(self.processes)

        # Update heartbeats for all receivers
        for dev_idx in self._receiver_info:
            proc_idx = dev_idx if dev_idx < len(self.processes) else None
            if proc_idx is not None and self.processes[proc_idx].poll() is None:
                self._update_receiver(dev_idx)  # heartbeat only
            elif proc_idx is not None:
                self._update_receiver(dev_idx, status="error",
                                      last_error=f"exited with code {self.processes[proc_idx].returncode}")
        r315 = self.stats.get("readings_315MHz", 0)
        r433 = self.stats.get("readings_433MHz", 0)
        est_v = max(1, self.stats["unique_sensors"] // 4) if self.stats["unique_sensors"] > 0 else 0

        log_stats(
            f"uptime={mins:02d}:{secs:02d}  "
            f"receivers={alive}/{total_receivers}  "
            f"signals={self.stats.get('total_signals', 0)}  "
            f"tpms_readings={self.stats['total_readings']} (315:{r315} 433:{r433})  "
            f"non_tpms={self.stats.get('non_tpms_signals', 0)}  "
            f"unknown={self.stats.get('unknown_signals', 0)} (filtered:{self.stats.get('unknown_filtered', 0)})  "
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
            # At 40-50 mph, a vehicle passes a ~200ft antenna range in ~3-4 seconds.
            # TPMS sensors transmit every ~1s when moving. Use a 5-second window
            # to group sensors from the same vehicle without merging consecutive cars.
            if current_time is None or (t - current_time).total_seconds() < 5:
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
        print(f"  Unknown signals:    {self.stats.get('unknown_signals', 0)}")
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
        # Flush any buffered analysis blocks
        for dev_idx in list(self._analysis_buffer.keys()):
            buf = self._analysis_buffer.pop(dev_idx)
            label = self._receiver_info.get(dev_idx, {}).get("label", "?")
            self._store_unknown(dev_idx, label, buf)

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

        # Auto-detect dongles and identify tuners
        dongles = detect_dongles()
        if not dongles:
            log_warn("No RTL-SDR devices detected — will try 2 devices anyway")
            dongles = [{"index": 0, "tuner": "unknown"}, {"index": 1, "tuner": "unknown"}]

        log_ok(f"Detected {len(dongles)} RTL-SDR dongle(s)")

        # Frequency assignment priority:
        # 1. Serial-based mapping (SERIAL_FREQ_MAP) — explicit, survives replug
        # 2. Tuner-based auto-assignment — R820T → 433MHz, E4000 → 315MHz
        # 3. Fallback — cycle through bands
        freq_list = list(FREQ_PRESETS.items())
        assignments = []
        assigned_indices = set()

        # Step 1: Check serial-based mapping
        for dongle in dongles:
            serial = dongle.get("serial", "")
            if serial in SERIAL_FREQ_MAP:
                label, freq = SERIAL_FREQ_MAP[serial]
                assignments.append((dongle["index"], freq, label))
                assigned_indices.add(dongle["index"])
                log_info(f"Serial mapping: {serial} → {label}")

        # Step 2: Assign remaining dongles by tuner type
        unassigned = [d for d in dongles if d["index"] not in assigned_indices]
        used_freqs = {a[1] for a in assignments}

        if unassigned:
            available_freqs = [(l, f) for l, f in freq_list if f not in used_freqs]
            if not available_freqs:
                available_freqs = list(freq_list)  # reuse if all taken

            for i, dongle in enumerate(unassigned):
                if available_freqs:
                    label, freq = available_freqs[i % len(available_freqs)]
                else:
                    label, freq = freq_list[i % len(freq_list)]
                if len(unassigned) > len(available_freqs) and i >= len(available_freqs):
                    label = f"{label}-{dongle['index']}"
                assignments.append((dongle["index"], freq, label))
                log_info(f"Auto-assigned device {dongle['index']} ({dongle['tuner']}) → {label}")

        print()
        log_info(f"Database: {DB_PATH}")
        log_info(f"All protocols enabled (all signals stored, TPMS enriched)")
        for dev_idx, freq, label in assignments:
            tuner = next((d["tuner"] for d in dongles if d["index"] == dev_idx), "?")
            log_info(f"Device {dev_idx} ({tuner}): {freq/1e6:.3f} MHz ({label})")
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
