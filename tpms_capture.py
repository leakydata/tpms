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
from collections import defaultdict, deque

DB_PATH = Path(__file__).parent / "tpms_data.db"

# Default station location (used when no GPS dongle is present)
DEFAULT_LAT = 40.224619417522824
DEFAULT_LON = -77.2428142810988

# Known TPMS protocol numbers in rtl_433.
TPMS_PROTOCOLS = {
    59, 60, 82, 88, 89, 90, 95, 110, 123, 140, 156, 168, 180, 186,
    201, 203, 208, 212, 225, 226, 241, 248, 252, 257, 275, 295, 298, 299,
}

# Disabled-by-default protocols we selectively enable.
# NOTE: Protocol 123 (Jansite TY02S) is excluded — its decoder is too
# permissive and produces many false positives. We keep 248 (Nissan)
# which has been verified to produce clean, consistent readings.
DISABLED_BY_DEFAULT = [
    6, 7, 13, 14, 24, 37, 48, 61, 62, 64, 72, 86, 101, 106, 107,
    117, 118, 129, 150, 162, 169, 198, 200, 216, 233, 242, 245,
    248, 260, 270,
]

# Protocols with known high false-positive rates. Readings from these
# decoders require stronger evidence (higher RSSI, or repeats within
# a short window) to be accepted.
PROMISCUOUS_PROTOCOLS = {
    "Jansite",              # protocol 180 — still loose
    "Jansite-Solar",
}

# Physical sanity limits for TPMS data
MIN_PRESSURE_KPA = 80   # ~12 psi — below this is flat or impossible
MAX_PRESSURE_KPA = 500  # ~73 psi — above this is commercial/truck only
MIN_TEMP_C = -30        # extreme cold
MAX_TEMP_C = 80         # hot tire under load
MIN_RSSI_DB = -30       # below this the signal is too weak to trust

# Frequency presets for TPMS bands
FREQ_PRESETS = {
    "315MHz": 315_000_000,   # North America
    "433MHz": 433_920_000,   # Europe / aftermarket
}

# Serial-to-frequency mapping. If a dongle has a known serial, assign
# it to a specific frequency. Overrides tuner-based auto-assignment.
#
# With 4 dongles we cover the major ISM/TPMS bands:
#   315 MHz  — US TPMS standard (mandated since 2007)
#   433.92 MHz — EU TPMS + aftermarket + many ISM devices
#   345 MHz  — GM/Chrysler TPMS (some models use this instead of 315)
#   868 MHz  — EU ISM band (some EU TPMS, key fobs, IoT sensors)
#
SERIAL_FREQ_MAP = {
    "TPMS_R820T":   ("433MHz", 433_920_000),   # R820T → EU TPMS + aftermarket
    "TPMS_R820T_2": ("315MHz", 315_000_000),   # R820T → US TPMS standard
    "TPMS_R820T_3": ("345MHz", 345_000_000),   # R820T → GM/Chrysler TPMS band
    "TPMS_E4000":   ("868MHz", 868_000_000),   # E4000 → EU ISM (TPMS + IoT)
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
        "ALTER TABLE readings ADD COLUMN confidence INTEGER",
        "ALTER TABLE readings ADD COLUMN crc_verified INTEGER",
        "ALTER TABLE unknown_signals ADD COLUMN pulse_count INTEGER",
        "ALTER TABLE unknown_signals ADD COLUMN width_ms REAL",
        "ALTER TABLE unknown_signals ADD COLUMN modulation TEXT",
        "ALTER TABLE unknown_signals ADD COLUMN raw_hex TEXT",
        "ALTER TABLE unknown_signals ADD COLUMN fingerprint TEXT",
        "ALTER TABLE unknown_signals ADD COLUMN triq_url TEXT",
        "ALTER TABLE unknown_signals ADD COLUMN iq_filename TEXT",
        # Re-identification tracking
        "ALTER TABLE sensors ADD COLUMN sighting_count INTEGER DEFAULT 1",
        "ALTER TABLE sensors ADD COLUMN mean_interval_secs REAL",
        "ALTER TABLE sensors ADD COLUMN last_interval_secs REAL",
        "ALTER TABLE sensors ADD COLUMN frequency_label TEXT",
        "ALTER TABLE sensors ADD COLUMN confidence_avg REAL",
        # Motion detection
        "ALTER TABLE readings ADD COLUMN direction TEXT",
        "ALTER TABLE readings ADD COLUMN rssi_trend REAL",
        # Receiver noise floor monitoring
        "ALTER TABLE receivers ADD COLUMN noise_floor_db REAL",
        "ALTER TABLE receivers ADD COLUMN noise_floor_baseline REAL",
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

    Uses rtl_test -t which reliably lists all devices with their serials
    and tuner types in a single call.
    """
    dongles = []
    try:
        # rtl_test -t lists devices quickly then benchmarks (slow).
        # We only need the device list, so use a short timeout.
        proc = subprocess.Popen(
            ["rtl_test", "-t"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True,
        )
        # Read lines until we've seen the device list
        lines = []
        import select
        while True:
            ready, _, _ = select.select([proc.stdout], [], [], 5)
            if not ready:
                break
            line = proc.stdout.readline()
            if not line:
                break
            lines.append(line)
            # Stop once we see "Using device" — the list is complete
            if "Using device" in line:
                break
        proc.kill()
        proc.wait()
        output = "".join(lines)
        n_devices = 0

        for line in output.split("\n"):
            line = line.strip()

            # "Found 4 device(s):"
            m = re.search(r"Found (\d+) device", line)
            if m:
                n_devices = int(m.group(1))
                continue

            # "  0:  Realtek, RTL2838UHIDIR, SN: TPMS_R820T"
            m = re.match(r"\s*(\d+):\s+.*,\s+SN:\s+(\S+)", line)
            if m:
                idx = int(m.group(1))
                serial = m.group(2)
                dongles.append({"index": idx, "tuner": "unknown", "serial": serial})
                continue

            # "Found Rafael Micro R820T tuner"
            if "Found" in line and "tuner" in line.lower():
                tuner = line.split("Found ")[-1].strip()
                # Assign to the last dongle that was being tested
                # rtl_test tests device 0, so this tuner info goes to
                # device 0. For other devices we'll probe individually.
                if dongles and dongles[0]["tuner"] == "unknown":
                    dongles[0]["tuner"] = tuner

        # rtl_test only reports the tuner for device 0.
        # For the rest, identify by serial name (which contains tuner info)
        # or probe individually.
        for d in dongles:
            if d["tuner"] == "unknown":
                serial = d["serial"].lower()
                if "e4000" in serial:
                    d["tuner"] = "Elonics E4000 tuner"
                elif "r820" in serial:
                    d["tuner"] = "Rafael Micro R820T tuner"

            log_sdr(f"Device {d['index']}: {d['tuner']}  serial={d['serial']}")

    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

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
        # Track recent TPMS decodes for repeat-confirmation:
        # (timestamp_utc, sensor_id, model, pressure_kpa, temperature_c)
        self._recent_decodes = deque(maxlen=500)
        self._pending_decodes = {}  # (sid, model) -> list of pending decodes awaiting repeat
        # Rolling RSSI log for motion/direction detection:
        # (timestamp, sensor_id, model, pressure, temp, rssi)
        self._recent_rssi_log = deque(maxlen=500)
        # Noise floor samples per device for monitoring dongle health
        self._noise_samples = defaultdict(lambda: deque(maxlen=50))

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

    def _validate_tpms(self, fields, data, rssi):
        """Validate a TPMS decode for physical plausibility.

        Returns (accept, reason). Rejects:
        - Missing sensor ID (can't track)
        - Pressure outside tire range (80-500 kPa)
        - Temperature outside plausible range (-30 to 80 C)
        - Very weak RSSI (<-30 dB) — corrupt bits
        - Unverified CRC/checksum at weak RSSI
        """
        sid = fields["sensor_id"]
        if not sid:
            return False, "missing sensor_id"

        pres = fields["pressure_kpa"]
        if pres is not None:
            if pres < MIN_PRESSURE_KPA or pres > MAX_PRESSURE_KPA:
                return False, f"pressure {pres:.0f} kPa out of range"

        temp = fields["temperature_c"]
        if temp is not None:
            if temp < MIN_TEMP_C or temp > MAX_TEMP_C:
                return False, f"temperature {temp:.0f}C out of range"

        if rssi is not None and rssi < MIN_RSSI_DB:
            return False, f"RSSI {rssi:.1f}dB too weak"

        # CRC/checksum validation — rtl_433 adds "mic" field when it
        # successfully validates. No mic at weak signal = probably corrupt.
        mic = str(data.get("mic", "")).upper()
        has_verified_crc = mic in ("CRC", "CHECKSUM", "PARITY")
        if not has_verified_crc and rssi is not None and rssi < -20:
            return False, f"no CRC verification at RSSI {rssi:.1f}dB"

        return True, "ok"

    def _is_duplicate_burst(self, sid, model, pressure_kpa, temp_c, window_secs=2):
        """Check if an identical decode (same sid+model+pressure+temp)
        was committed within the last N seconds. Multiple transmissions
        of the same reading from a burst should be stored once.
        """
        now = datetime.now(timezone.utc)
        for (t, s, m, p, temp) in self._recent_decodes:
            age = (now - t).total_seconds()
            if age > window_secs:
                continue
            if s == sid and m == model:
                # Same sensor within window
                if (pressure_kpa == p or
                    (pressure_kpa is not None and p is not None and
                     abs(pressure_kpa - p) < 1)):
                    # Same pressure (within 1 kPa) = duplicate
                    if (temp == temp_c or
                        (temp is not None and temp_c is not None and
                         abs(temp - temp_c) < 2)):
                        return True
        return False

    def _is_pressure_jump(self, sid, pressure_kpa, window_secs=60):
        """Flag readings where same sensor's pressure jumps >50 kPa
        within a short window — likely a decode error on one of them."""
        if pressure_kpa is None:
            return False, None
        now = datetime.now(timezone.utc)
        for (t, s, _m, p, _temp) in self._recent_decodes:
            age = (now - t).total_seconds()
            if age > window_secs:
                continue
            if s == sid and p is not None:
                diff = abs(p - pressure_kpa)
                if diff > 50:
                    return True, diff
        return False, None

    def _count_recent_repeats(self, sid, model, pressure_kpa, window_secs=15):
        """Count how many times this sensor_id+model appeared in the
        last N seconds with the same pressure (within 10 kPa)."""
        now = datetime.now(timezone.utc)
        count = 0
        for (t, s, m, p, _temp) in self._recent_decodes:
            age = (now - t).total_seconds()
            if age > window_secs:
                continue
            if s == sid and m == model:
                # Same sensor — check pressure consistency
                if pressure_kpa is None or p is None:
                    count += 1
                elif abs(p - pressure_kpa) <= 10:
                    count += 1
        return count

    def _compute_confidence(self, rssi, snr, mic, model, repeats, pressure_kpa):
        """Compute a confidence score (0-100) for a TPMS decode.

        Factors:
        - RSSI strength (up to 30 points)
        - SNR (up to 15 points)
        - CRC verification (15 points)
        - Repeat confirmations (up to 25 points)
        - Pressure plausibility (up to 5 points)
        - Promiscuous decoder penalty (-10 points)
        """
        score = 30  # base score

        if rssi is not None:
            if rssi > -10: score += 30
            elif rssi > -15: score += 25
            elif rssi > -20: score += 15
            elif rssi > -25: score += 5
            else: score -= 10

        if snr is not None:
            if snr > 25: score += 15
            elif snr > 15: score += 10
            elif snr > 8: score += 5

        if mic and str(mic).upper() in ("CRC", "CHECKSUM", "PARITY"):
            score += 15

        score += min(25, repeats * 8)

        if pressure_kpa is not None:
            if 180 <= pressure_kpa <= 320:  # typical passenger car range
                score += 5

        if model in PROMISCUOUS_PROTOCOLS:
            score -= 10

        return max(0, min(100, score))

    def _detect_direction(self, sid, model, window_secs=10):
        """Detect vehicle direction from RSSI trend across recent decodes.

        Returns (direction, rssi_slope_db_per_s):
        - "approaching" if RSSI is rising
        - "departing" if RSSI is falling
        - "stationary" if flat
        - (None, None) if insufficient data
        """
        now = datetime.now(timezone.utc)
        points = []  # (age_secs, rssi)
        for (t, s, m, _p, _temp, rssi_val) in self._recent_rssi_log:
            if s == sid and m == model:
                age = (now - t).total_seconds()
                if age < window_secs and rssi_val is not None:
                    points.append((age, rssi_val))

        if len(points) < 3:
            return None, None

        # Simple linear regression: RSSI vs negative age (age=0 is now)
        # Rising RSSI over time = approaching
        n = len(points)
        x_vals = [-p[0] for p in points]  # negate so larger = more recent
        y_vals = [p[1] for p in points]
        mean_x = sum(x_vals) / n
        mean_y = sum(y_vals) / n
        num = sum((x - mean_x) * (y - mean_y) for x, y in zip(x_vals, y_vals))
        den = sum((x - mean_x) ** 2 for x in x_vals)
        if den == 0:
            return "stationary", 0.0

        slope = num / den  # dB per second (positive = rising = approaching)

        if slope > 0.5:
            return "approaching", slope
        elif slope < -0.5:
            return "departing", slope
        else:
            return "stationary", slope

    def _validate_sensor_id(self, sid, model):
        """Validate sensor ID matches the model's expected format.

        Uses observed ID length statistics: learns from the first several
        readings of each model what the typical hex ID length is, and
        rejects outliers.
        """
        if not sid:
            return False, "empty id"
        if not all(c in "0123456789abcdefABCDEF" for c in sid):
            return False, f"id '{sid}' not hex"
        # Track expected length per model (learned from real data)
        if not hasattr(self, '_model_id_lengths'):
            self._model_id_lengths = defaultdict(list)
        self._model_id_lengths[model].append(len(sid))
        if len(self._model_id_lengths[model]) > 3:
            # Learned enough to validate
            lengths = self._model_id_lengths[model][-20:]  # keep rolling window
            self._model_id_lengths[model] = lengths
            common = max(set(lengths), key=lengths.count)
            # Allow ±2 chars flexibility
            if abs(len(sid) - common) > 2:
                return False, f"id length {len(sid)} differs from expected {common} for {model}"
        return True, "ok"

    def _commit_tpms(self, data, fields, freq_label):
        """Store a TPMS decode in both signals and readings tables, update sensor.

        Applies sanity filters to reject false decodes. Promiscuous decoders
        (Jansite, etc.) require stronger evidence — either a strong RSSI or
        at least one repeat within 15 seconds with consistent pressure.
        """
        timestamp = data.get("time", datetime.now(timezone.utc).isoformat())
        model = data.get("model", "unknown")
        protocol = data.get("protocol", "")
        freq_mhz = data.get("freq", None)
        rssi = data.get("rssi", None)
        snr = data.get("snr", None)
        noise = data.get("noise", None)
        sid = fields["sensor_id"]

        # Physical sanity check
        accept, reason = self._validate_tpms(fields, data, rssi)
        if not accept:
            self.stats["rejected_invalid"] += 1
            log_info(f"[{freq_label}] REJECT  {model} {sid or '?'}: {reason}")
            return

        # Cross-burst duplicate suppression: same sensor transmitting the
        # same reading within 2 seconds = one physical event, not multiple.
        if self._is_duplicate_burst(
            sid, model, fields["pressure_kpa"], fields["temperature_c"]
        ):
            self.stats["rejected_duplicate"] += 1
            log_info(f"[{freq_label}] SKIP    {model} {sid}: duplicate within 2s")
            return

        # Pressure jump detection: same sensor changing pressure by >50 kPa
        # in under 60 seconds is physically impossible — one reading is wrong.
        is_jump, jump_amt = self._is_pressure_jump(sid, fields["pressure_kpa"])
        if is_jump:
            self.stats["rejected_pressure_jump"] += 1
            log_info(
                f"[{freq_label}] REJECT  {model} {sid}: "
                f"pressure jump {jump_amt:.0f} kPa in <60s (suspect decode)"
            )
            return

        # Promiscuous decoders need stronger evidence
        is_promiscuous = model in PROMISCUOUS_PROTOCOLS
        if is_promiscuous:
            repeats = self._count_recent_repeats(sid, model, fields["pressure_kpa"])
            has_strong_signal = rssi is not None and rssi > -15
            if repeats == 0 and not has_strong_signal:
                self.stats["rejected_low_confidence"] += 1
                log_info(
                    f"[{freq_label}] REJECT  {model} {sid}: "
                    f"low confidence (RSSI={rssi}, repeats={repeats}) — "
                    f"waiting for repeat"
                )
                # Track it so future repeats can find it
                self._recent_decodes.append(
                    (datetime.now(timezone.utc), sid, model,
                     fields["pressure_kpa"], fields["temperature_c"])
                )
                return

        # Universal weak-signal confidence check (applies to ALL decoders):
        # RSSI < -25 dB with no CRC verification = reject
        mic = str(data.get("mic", "")).upper()
        has_verified_crc = mic in ("CRC", "CHECKSUM", "PARITY")
        if rssi is not None and rssi < -25 and not has_verified_crc:
            self.stats["rejected_weak_unverified"] += 1
            log_info(
                f"[{freq_label}] REJECT  {model} {sid}: "
                f"RSSI {rssi:.1f}dB + no CRC verification"
            )
            return

        # Sensor ID format validation per model
        id_ok, id_reason = self._validate_sensor_id(sid, model)
        if not id_ok:
            self.stats["rejected_invalid_id"] += 1
            log_info(f"[{freq_label}] REJECT  {model} {sid}: {id_reason}")
            return

        # Track this decode for future repeat detection
        now_utc = datetime.now(timezone.utc)
        self._recent_decodes.append(
            (now_utc, sid, model,
             fields["pressure_kpa"], fields["temperature_c"])
        )
        self._recent_rssi_log.append(
            (now_utc, sid, model, fields["pressure_kpa"],
             fields["temperature_c"], rssi)
        )

        # Compute confidence score
        repeats = self._count_recent_repeats(sid, model, fields["pressure_kpa"])
        confidence = self._compute_confidence(
            rssi, snr, data.get("mic"), model, repeats, fields["pressure_kpa"]
        )
        crc_verified = 1 if has_verified_crc else 0

        # Motion/direction detection
        direction, rssi_slope = self._detect_direction(sid, model)

        # Re-identification tracking: compute interval since last sighting
        is_new = sid not in self.unique_sensors
        last_interval = None
        if not is_new:
            # Query existing last_seen from DB
            with self.lock:
                prev = self.conn.execute(
                    "SELECT last_seen FROM sensors WHERE sensor_id = ?", (sid,)
                ).fetchone()
                if prev and prev[0]:
                    try:
                        prev_t = datetime.fromisoformat(prev[0].replace("Z", "+00:00"))
                        if prev_t.tzinfo is None:
                            prev_t = prev_t.replace(tzinfo=timezone.utc)
                        last_interval = (now_utc - prev_t).total_seconds()
                        # Only count as a new "sighting" if >60 seconds apart
                        # (otherwise it's the same pass-by event)
                    except Exception:
                        pass

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

            # Store in TPMS readings table (with confidence + direction)
            self.conn.execute(
                """INSERT INTO readings
                   (signal_id, timestamp, frequency_mhz, protocol, model, sensor_id,
                    pressure_kpa, temperature_c, battery_ok, flags, raw_json,
                    confidence, crc_verified, direction, rssi_trend)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (signal_id, timestamp, freq_mhz, str(protocol), model, sid,
                 fields["pressure_kpa"], fields["temperature_c"],
                 fields["battery_ok"], fields["flags"], json.dumps(data),
                 confidence, crc_verified, direction, rssi_slope),
            )

            # Upsert sensor record with re-identification tracking
            is_new_sighting = last_interval is None or last_interval > 60

            self.conn.execute("""
                INSERT INTO sensors
                    (sensor_id, model, first_seen, last_seen, reading_count,
                     min_pressure_kpa, max_pressure_kpa, min_temperature_c, max_temperature_c,
                     last_pressure_kpa, last_temperature_c, last_battery_ok, last_rssi,
                     sighting_count, mean_interval_secs, last_interval_secs,
                     frequency_label, confidence_avg)
                VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, NULL, ?, ?)
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
                    last_rssi = COALESCE(excluded.last_rssi, last_rssi),
                    frequency_label = excluded.frequency_label,
                    sighting_count = sighting_count + CASE WHEN ? THEN 1 ELSE 0 END,
                    last_interval_secs = CASE WHEN ? THEN ? ELSE last_interval_secs END,
                    mean_interval_secs = CASE
                        WHEN ? AND mean_interval_secs IS NULL THEN ?
                        WHEN ? THEN (mean_interval_secs * (sighting_count - 1) + ?) / sighting_count
                        ELSE mean_interval_secs
                    END,
                    confidence_avg = CASE
                        WHEN confidence_avg IS NULL THEN ?
                        ELSE (confidence_avg * (reading_count - 1) + ?) / reading_count
                    END
            """, (
                sid, model, timestamp, timestamp,
                fields["pressure_kpa"], fields["pressure_kpa"],
                fields["temperature_c"], fields["temperature_c"],
                fields["pressure_kpa"], fields["temperature_c"],
                fields["battery_ok"], rssi,
                freq_label, confidence,
                # ON CONFLICT params:
                is_new_sighting,
                is_new_sighting, last_interval,
                is_new_sighting, last_interval,
                is_new_sighting, last_interval,
                confidence, confidence,
            ))

            self.conn.commit()

            self.stats["total_signals"] += 1
            self.stats["total_readings"] += 1
            self.stats[f"readings_{freq_label}"] += 1
            self.unique_sensors.add(sid)
            self.stats["unique_sensors"] = len(self.unique_sensors)
            self.sensor_models[sid] = model

        # Update dongle noise floor for health monitoring
        if noise is not None:
            dev_idx_noise = self._freq_label_to_device(freq_label)
            if dev_idx_noise is not None:
                self._noise_samples[dev_idx_noise].append(noise)

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

        # Confidence + direction + CRC flags
        conf_color = (
            C["green"] if confidence >= 70
            else C["yellow"] if confidence >= 40
            else C["red"]
        )
        parts.append(f"conf={conf_color}{confidence}{C['reset']}")
        if crc_verified:
            parts.append(f"{C['green']}✓CRC{C['reset']}")
        if direction:
            arrow = "→" if direction == "approaching" else "←" if direction == "departing" else "·"
            parts.append(f"{arrow}{direction}")
        if last_interval is not None and not is_new_sighting:
            # Part of same pass-by event
            parts.append(f"burst+{last_interval:.0f}s")
        elif last_interval is not None:
            # Re-identification! Sensor seen before, but different event
            mins = last_interval / 60
            if mins < 60:
                parts.append(f"{C['magenta']}↻ seen {mins:.0f}m ago{C['reset']}")
            else:
                parts.append(f"{C['magenta']}↻ seen {mins/60:.1f}h ago{C['reset']}")

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

    def _check_noise_floors(self):
        """Monitor dongle noise floors, warn on degradation."""
        for dev_idx, samples in self._noise_samples.items():
            if len(samples) < 10:
                continue
            recent = list(samples)[-10:]
            avg_recent = sum(recent) / len(recent)

            # Update DB with current noise floor
            try:
                with self.lock:
                    # Fetch existing baseline
                    row = self.conn.execute(
                        "SELECT noise_floor_baseline FROM receivers WHERE device_index = ?",
                        (dev_idx,)
                    ).fetchone()
                    baseline = row[0] if row and row[0] else None

                    if baseline is None:
                        # Set initial baseline
                        self.conn.execute(
                            "UPDATE receivers SET noise_floor_baseline = ?, noise_floor_db = ? WHERE device_index = ?",
                            (avg_recent, avg_recent, dev_idx),
                        )
                    else:
                        # Update current noise floor
                        self.conn.execute(
                            "UPDATE receivers SET noise_floor_db = ? WHERE device_index = ?",
                            (avg_recent, dev_idx),
                        )
                        # Alert on degradation (noise rising by 6+ dB = 4x louder)
                        if avg_recent - baseline > 6:
                            info = self._receiver_info.get(dev_idx, {})
                            label = info.get("label", f"device{dev_idx}")
                            log_warn(
                                f"[{label}] noise floor {avg_recent:+.1f}dB "
                                f"rose {avg_recent - baseline:+.1f}dB above baseline "
                                f"({baseline:+.1f}dB) — check antenna/interference"
                            )
                    self.conn.commit()
            except sqlite3.OperationalError:
                pass  # table not ready yet

    def _maybe_export_csv(self):
        """Once per day, export today's readings to a CSV archive."""
        now = datetime.now()
        today_str = now.strftime("%Y-%m-%d")
        last_export = getattr(self, "_last_csv_export_date", None)
        if last_export == today_str:
            return
        if last_export is None:
            self._last_csv_export_date = today_str
            return  # don't export on first run

        # New day — export the previous day's data
        export_dir = Path(__file__).parent / "exports"
        export_dir.mkdir(exist_ok=True)
        csv_path = export_dir / f"readings_{last_export}.csv"

        try:
            with self.lock:
                rows = self.conn.execute(
                    """SELECT timestamp, frequency_mhz, protocol, model, sensor_id,
                              pressure_kpa, temperature_c, battery_ok, flags,
                              confidence, crc_verified, direction
                       FROM readings
                       WHERE date(timestamp) = ?
                       ORDER BY timestamp""",
                    (last_export,)
                ).fetchall()

            with csv_path.open("w") as f:
                f.write(
                    "timestamp,frequency_mhz,protocol,model,sensor_id,"
                    "pressure_kpa,temperature_c,battery_ok,flags,"
                    "confidence,crc_verified,direction\n"
                )
                for row in rows:
                    f.write(",".join(str(v) if v is not None else "" for v in row) + "\n")

            log_ok(f"Exported {len(rows)} readings for {last_export} → {csv_path}")
        except Exception as e:
            log_warn(f"CSV export failed: {e}")

        self._last_csv_export_date = today_str

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

        # Check noise floors and maybe export CSV
        self._check_noise_floors()
        self._maybe_export_csv()

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
            f"rejected=(invalid:{self.stats.get('rejected_invalid', 0)} "
            f"dup:{self.stats.get('rejected_duplicate', 0)} "
            f"lowconf:{self.stats.get('rejected_low_confidence', 0)} "
            f"weak:{self.stats.get('rejected_weak_unverified', 0)} "
            f"jump:{self.stats.get('rejected_pressure_jump', 0)})  "
            f"sensors={self.stats['unique_sensors']}  "
            f"est_vehicles=~{est_v}"
        )

    def correlate_vehicles(self):
        """Group sensors into vehicles using time + model + pressure + band.

        A vehicle has 4-5 tires. Real vehicle groups satisfy:
        - Sensors appear within a short time window (5s at highway speed)
        - Tires usually have the same TPMS manufacturer (same model)
        - Tires on the same vehicle have similar pressure (±30 kPa)
        - Same frequency band (a vehicle uses one band)
        - 2-5 sensors per vehicle (singletons are noise)
        """
        log_info("Correlating sensors into vehicle groups...")
        cur = self.conn.execute("""
            SELECT sensor_id, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
                   COUNT(*) as reading_count, model,
                   AVG(pressure_kpa) as avg_pressure,
                   AVG(frequency_mhz) as avg_freq
            FROM readings
            WHERE confidence IS NULL OR confidence >= 40
            GROUP BY sensor_id
            ORDER BY first_seen
        """)
        sensors = cur.fetchall()
        if not sensors:
            log_warn("No sensors captured — nothing to correlate")
            return

        # Build individual "burst events" (time-adjacent sensors)
        bursts = []
        current, current_time = [], None
        for row in sensors:
            sid, first_seen, last_seen, count, model, avg_p, avg_freq = row
            t = datetime.fromisoformat(first_seen)
            if current_time is None or (t - current_time).total_seconds() < 5:
                current.append(row)
                if current_time is None:
                    current_time = t
            else:
                if current:
                    bursts.append(current)
                current = [row]
                current_time = t
        if current:
            bursts.append(current)

        # Split each burst into vehicle groups based on model/pressure/band
        vehicle_groups = []
        for burst in bursts:
            # If single sensor, it's either a singleton or part of a larger
            # vehicle we didn't catch fully — keep it but flag
            if len(burst) == 1:
                vehicle_groups.append(burst)
                continue

            # Group by (model, frequency_band)
            subgroups = defaultdict(list)
            for row in burst:
                sid, fs, ls, cnt, model, avg_p, avg_freq = row
                band = "315" if (avg_freq or 0) < 400 else "433"
                subgroups[(model, band)].append(row)

            # Within each subgroup, split further by pressure similarity
            for sg_key, sg_rows in subgroups.items():
                # Sort by pressure, group nearby ones
                sg_rows.sort(key=lambda r: r[5] or 0)
                clusters = []
                current_cluster = []
                last_p = None
                for row in sg_rows:
                    p = row[5]
                    if (last_p is None or p is None or
                        abs((p or 0) - (last_p or 0)) < 30):
                        current_cluster.append(row)
                    else:
                        if current_cluster:
                            clusters.append(current_cluster)
                        current_cluster = [row]
                    last_p = p
                if current_cluster:
                    clusters.append(current_cluster)
                vehicle_groups.extend(clusters)

        # Store vehicle groups with quality indicators
        for group in vehicle_groups:
            sensor_ids = sorted(set(r[0] for r in group))
            vehicle_hash = "|".join(sensor_ids)
            first_seen = min(r[1] for r in group)
            last_seen = max(r[2] for r in group)
            # Quality score based on tire count (4 tires = ideal vehicle)
            n = len(sensor_ids)
            notes = None
            if n == 1:
                notes = "singleton (probably incomplete vehicle)"
            elif n >= 4:
                notes = f"high confidence ({n} tires detected)"
            elif n >= 2:
                notes = f"partial ({n} tires)"

            self.conn.execute("""
                INSERT INTO vehicles (vehicle_hash, sensor_ids, first_seen, last_seen, sighting_count, notes)
                VALUES (?, ?, ?, ?, 1, ?)
                ON CONFLICT(vehicle_hash) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    sighting_count = sighting_count + 1,
                    notes = excluded.notes
            """, (vehicle_hash, json.dumps(sensor_ids), first_seen, last_seen, notes))
        self.conn.commit()

        full_vehicles = [g for g in vehicle_groups if len(g) >= 2]
        singletons = [g for g in vehicle_groups if len(g) == 1]

        log_ok(
            f"Correlated: {len(vehicle_groups)} groups — "
            f"{len(full_vehicles)} likely vehicles ({len(singletons)} singletons)"
        )

        for i, group in enumerate(vehicle_groups, 1):
            sensor_ids = sorted(set(r[0] for r in group))
            models = sorted(set(r[4] for r in group))
            pressures = [r[5] for r in group if r[5] is not None]
            pres_range = ""
            if pressures:
                pres_range = f"  pressure={min(pressures):.0f}-{max(pressures):.0f}kPa"
            tag = "" if len(sensor_ids) >= 2 else " (singleton)"
            log_info(f"  Vehicle {i}: {len(sensor_ids)} tire(s) — "
                     f"{', '.join(models)}{pres_range}{tag}")
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
