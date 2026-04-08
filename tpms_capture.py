#!/usr/bin/env python3
"""
TPMS Sensor Capture Tool
Captures tire pressure monitoring system (TPMS) broadcasts from passing vehicles
using rtl_433 and two RTL-SDR dongles (315 MHz + 433.92 MHz).

For research on anti-stalking / vehicle tracking privacy.
"""

import json
import sqlite3
import subprocess
import signal
import shutil
import sys
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

DB_PATH = Path(__file__).parent / "tpms_data.db"

# TPMS protocol numbers in rtl_433
TPMS_PROTOCOLS = [
    59,   # Steelmate TPMS
    60,   # Schrader TPMS
    82,   # Citroen TPMS
    88,   # Toyota TPMS
    89,   # Ford TPMS
    90,   # Renault TPMS
    95,   # Schrader TPMS EG53MA4
    110,  # PMV-107J (Toyota) TPMS
    123,  # Jansite TPMS Model TY02S
    140,  # Elantra2012 TPMS
    156,  # Abarth 124 Spider TPMS
    168,  # Schrader TPMS SMD3MA4 (Subaru)
    180,  # Jansite TPMS Model Solar
    186,  # Hyundai TPMS (VDO)
    201,  # Unbranded SolarTPMS for trucks
    203,  # Porsche Boxster/Cayman TPMS
    208,  # AVE TPMS
    212,  # Renault 0435R TPMS
    225,  # TyreGuard 400 TPMS
    226,  # Kia TPMS
    241,  # EezTire E618 / Carchet / TST-507 TPMS
    248,  # Nissan TPMS
    252,  # BMW Gen4-Gen5 / Audi / HUF/Beru / Continental / Schrader
    257,  # BMW Gen2 and Gen3 TPMS
    275,  # GM-Aftermarket TPMS
    295,  # Airpuxem TPMS
    298,  # TRW TPMS OOK
    299,  # TRW TPMS FSK
]

# ── Logging helpers ──────────────────────────────────────────────────────────

COLORS = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "red":     "\033[31m",
    "green":   "\033[32m",
    "yellow":  "\033[33m",
    "blue":    "\033[34m",
    "magenta": "\033[35m",
    "cyan":    "\033[36m",
    "white":   "\033[37m",
}

# Disable colors if not a TTY
if not sys.stdout.isatty():
    COLORS = {k: "" for k in COLORS}

C = COLORS  # short alias


def _ts():
    """Return a formatted timestamp for log lines."""
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
    """Log a received TPMS reading."""
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['green']}  RX{C['reset']}  {msg}", flush=True)


def log_db(msg):
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['magenta']}  DB{C['reset']}  {msg}", flush=True)


def log_sdr(msg):
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['blue']} SDR{C['reset']}  {msg}", flush=True)


def log_stats(msg):
    print(f"{C['dim']}[{_ts()}]{C['reset']} {C['white']}{C['bold']}STAT{C['reset']}  {msg}", flush=True)


# ── Database ─────────────────────────────────────────────────────────────────

def init_db():
    """Create the SQLite database and tables."""
    log_db(f"Opening database: {DB_PATH}")
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    log_db("Set journal_mode=WAL")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    conn.execute("CREATE INDEX IF NOT EXISTS idx_readings_sensor_id ON readings(sensor_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_readings_timestamp ON readings(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vehicles_hash ON vehicles(vehicle_hash)")
    conn.commit()

    # Report existing data
    cur = conn.execute("SELECT COUNT(*) FROM readings")
    existing = cur.fetchone()[0]
    cur = conn.execute("SELECT COUNT(DISTINCT sensor_id) FROM readings")
    existing_sensors = cur.fetchone()[0]
    if existing > 0:
        log_db(f"Existing data: {existing} readings, {existing_sensors} unique sensors")
    else:
        log_db("Database initialized (empty — fresh start)")

    return conn


# ── Field extraction ─────────────────────────────────────────────────────────

def extract_sensor_fields(data: dict) -> dict:
    """Extract relevant TPMS fields from an rtl_433 JSON message."""
    sensor_id = str(
        data.get("id")
        or data.get("ID")
        or data.get("sensor_id")
        or data.get("code")
        or data.get("address")
        or ""
    )

    pressure = (
        data.get("pressure_kPa")
        or data.get("pressure_PSI")
        or data.get("pressure_bar")
        or None
    )
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
    """Check if a decoded message is a TPMS reading."""
    model = data.get("model", "").lower()
    if any(kw in model for kw in ("tpms", "tire", "tyre", "pressure")):
        return True
    proto = data.get("protocol")
    if proto and int(proto) in TPMS_PROTOCOLS:
        return True
    return False


# ── Main capture class ───────────────────────────────────────────────────────

class TPMSCapture:
    def __init__(self):
        self.conn = init_db()
        self.processes = []
        self.running = True
        self.lock = threading.Lock()
        self.stats = defaultdict(int)
        self.unique_sensors = set()
        self.sensor_models = {}          # sensor_id -> model
        self.sensor_last_seen = {}       # sensor_id -> timestamp
        self.start_time = datetime.now(timezone.utc)
        self.last_status_time = time.monotonic()
        self.stderr_threads = []

    def build_rtl433_cmd(self, device_index: int, frequency: float) -> list:
        """Build rtl_433 command for a specific device and frequency."""
        protocol_args = []
        for p in TPMS_PROTOCOLS:
            protocol_args.extend(["-R", str(p)])

        cmd = [
            "rtl_433",
            "-d", str(device_index),
            "-f", str(int(frequency)),
            "-M", "time:utc",
            "-M", "protocol",
            "-M", "level",
            "-F", "json",
        ] + protocol_args

        return cmd

    def _stream_stderr(self, proc, freq_label: str):
        """Read and log stderr from an rtl_433 process."""
        for line in proc.stderr:
            line = line.strip()
            if not line:
                continue
            # Classify rtl_433 stderr messages
            lower = line.lower()
            if "if you want" in lower:
                # Informational hint from rtl_433, not an actual error
                log_sdr(f"[{freq_label}] {line}")
            elif "error" in lower or "fail" in lower:
                log_error(f"[{freq_label}] {line}")
            elif "pll not locked" in lower:
                log_warn(f"[{freq_label}] {line} (usually harmless at startup)")
            elif "warning" in lower or "warn" in lower:
                log_warn(f"[{freq_label}] {line}")
            else:
                log_sdr(f"[{freq_label}] {line}")

    def process_line(self, line: str, freq_label: str):
        """Process a single JSON line from rtl_433."""
        line = line.strip()
        if not line:
            return

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            log_warn(f"[{freq_label}] Non-JSON output: {line[:120]}")
            return

        model = data.get("model", "unknown")

        if not is_tpms(data):
            log_info(f"[{freq_label}] Ignored non-TPMS decode: model={model}")
            return

        fields = extract_sensor_fields(data)
        timestamp = data.get("time", datetime.now(timezone.utc).isoformat())
        protocol = data.get("protocol", "")
        freq_mhz = data.get("freq", None)
        snr = data.get("snr", None)
        rssi = data.get("rssi", None)
        noise = data.get("noise", None)

        is_new_sensor = fields["sensor_id"] not in self.unique_sensors

        with self.lock:
            self.conn.execute(
                """INSERT INTO readings
                   (timestamp, frequency_mhz, protocol, model, sensor_id,
                    pressure_kpa, temperature_c, battery_ok, flags, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    timestamp,
                    freq_mhz,
                    str(protocol),
                    model,
                    fields["sensor_id"],
                    fields["pressure_kpa"],
                    fields["temperature_c"],
                    fields["battery_ok"],
                    fields["flags"],
                    json.dumps(data),
                ),
            )
            self.conn.commit()

            self.stats["total_readings"] += 1
            self.stats[f"readings_{freq_label}"] += 1
            self.unique_sensors.add(fields["sensor_id"])
            self.stats["unique_sensors"] = len(self.unique_sensors)
            self.sensor_models[fields["sensor_id"]] = model
            self.sensor_last_seen[fields["sensor_id"]] = timestamp

        # ── Build detailed log line ──
        sid = fields["sensor_id"]
        psi_str = ""
        if fields["pressure_kpa"]:
            psi_str = f"  pressure={fields['pressure_kpa']:.1f}kPa ({fields['pressure_kpa']/6.89476:.1f}psi)"
        temp_str = ""
        if fields["temperature_c"] is not None:
            temp_str = f"  temp={fields['temperature_c']:.1f}C"
        batt_str = ""
        if fields["battery_ok"] is not None:
            batt_str = f"  batt={'OK' if fields['battery_ok'] else 'LOW'}"
        flag_str = ""
        if fields["flags"]:
            flag_str = f"  flags={fields['flags']}"
        signal_str = ""
        if snr is not None:
            signal_str += f"  SNR={snr:.1f}dB"
        if rssi is not None:
            signal_str += f"  RSSI={rssi:.1f}dB"
        if noise is not None:
            signal_str += f"  noise={noise:.1f}dB"
        freq_str = f"  freq={freq_mhz:.3f}MHz" if freq_mhz else ""

        new_tag = f"  {C['yellow']}** NEW SENSOR **{C['reset']}" if is_new_sensor else ""

        log_rx(
            f"[{freq_label}] {C['bold']}{model}{C['reset']}  "
            f"id={C['cyan']}{sid}{C['reset']}"
            f"{psi_str}{temp_str}{batt_str}{flag_str}{signal_str}{freq_str}"
            f"  proto={protocol}{new_tag}"
        )

        if is_new_sensor:
            log_db(f"Stored new sensor {sid} ({model}) — "
                   f"{self.stats['unique_sensors']} unique sensors total")

    def run_receiver(self, device_index: int, frequency: float, freq_label: str):
        """Run rtl_433 for one dongle and process its output."""
        cmd = self.build_rtl433_cmd(device_index, frequency)
        log_sdr(f"[{freq_label}] Launching rtl_433 on device {device_index}")
        log_sdr(f"[{freq_label}] Command: {' '.join(cmd)}")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            log_error(f"[{freq_label}] rtl_433 not found! Install it first.")
            return
        except Exception as e:
            log_error(f"[{freq_label}] Failed to start rtl_433: {e}")
            return

        self.processes.append(proc)
        log_ok(f"[{freq_label}] rtl_433 started (PID {proc.pid})")

        # Stream stderr in a separate thread so we see SDR init messages
        stderr_t = threading.Thread(
            target=self._stream_stderr,
            args=(proc, freq_label),
            daemon=True,
        )
        stderr_t.start()
        self.stderr_threads.append(stderr_t)

        log_info(f"[{freq_label}] Listening for TPMS signals...")

        while self.running:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    exit_code = proc.returncode
                    if exit_code != 0 and self.running:
                        log_error(f"[{freq_label}] rtl_433 exited with code {exit_code}")
                    break
                continue
            self.process_line(line, freq_label)

        if self.running:
            log_warn(f"[{freq_label}] Receiver stopped unexpectedly")

    def print_periodic_status(self):
        """Print a status line every 30 seconds showing we're alive."""
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)

        alive_procs = sum(1 for p in self.processes if p.poll() is None)
        readings_315 = self.stats.get("readings_315MHz", 0)
        readings_433 = self.stats.get("readings_433MHz", 0)

        log_stats(
            f"uptime={mins:02d}:{secs:02d}  "
            f"receivers={alive_procs}/2  "
            f"readings={self.stats['total_readings']} "
            f"(315MHz:{readings_315} 433MHz:{readings_433})  "
            f"unique_sensors={self.stats['unique_sensors']}  "
            f"est_vehicles=~{max(1, self.stats['unique_sensors'] // 4) if self.stats['unique_sensors'] > 0 else 0}"
        )

    def correlate_vehicles(self):
        """Group sensor IDs that appear within short time windows into vehicles."""
        log_info("Correlating sensors into vehicle groups...")
        cur = self.conn.execute("""
            SELECT sensor_id, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
                   COUNT(*) as reading_count, model
            FROM readings
            GROUP BY sensor_id
            ORDER BY first_seen
        """)
        sensors = cur.fetchall()

        if not sensors:
            log_warn("No sensors captured — nothing to correlate")
            return

        groups = []
        current_group = []
        current_time = None

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
                    last_seen = excluded.last_seen,
                    sighting_count = sighting_count + 1
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
        """Print session summary."""
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)

        print(f"\n{C['bold']}{'='*70}{C['reset']}")
        print(f"{C['bold']}  TPMS Capture Session Summary{C['reset']}")
        print(f"{C['bold']}{'='*70}{C['reset']}")
        print(f"  Duration:           {mins}m {secs}s")
        print(f"  Total readings:     {self.stats['total_readings']}")
        print(f"  Unique sensor IDs:  {self.stats['unique_sensors']}")
        print(f"  Est. vehicles:      ~{max(1, self.stats['unique_sensors'] // 4) if self.stats['unique_sensors'] > 0 else 0}")
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
        """Clean shutdown."""
        if not self.running:
            return
        print()
        log_info("Shutdown signal received")
        self.running = False

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
        """Verify rtl_433 and SDR dongles are available before starting."""
        log_info("Checking prerequisites...")

        # Check rtl_433
        rtl_path = shutil.which("rtl_433")
        if not rtl_path:
            log_error("rtl_433 not found in PATH!")
            log_error("Install it: https://github.com/merbanan/rtl_433")
            return False
        log_ok(f"rtl_433 found: {rtl_path}")

        # Get version
        try:
            ver = subprocess.run(
                ["rtl_433", "-V"],
                capture_output=True, text=True, timeout=5
            )
            version_line = (ver.stdout + ver.stderr).strip().split("\n")[0]
            log_ok(f"rtl_433 version: {version_line}")
        except Exception:
            log_warn("Could not determine rtl_433 version")

        # Check for dongles
        try:
            result = subprocess.run(
                ["rtl_test", "-t"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout + result.stderr
            if "Found 0 device" in output:
                log_error("No RTL-SDR devices found!")
                return False

            for line in output.split("\n"):
                line = line.strip()
                if line.startswith("Found") or ("Realtek" in line) or ("Using device" in line):
                    log_sdr(line)
        except FileNotFoundError:
            log_warn("rtl_test not available — skipping device check")
        except subprocess.TimeoutExpired:
            log_ok("RTL-SDR devices detected (rtl_test responded)")

        return True

    def run(self):
        """Main entry point — run both receivers."""
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

        print(f"\n{C['bold']}{C['cyan']}╔══════════════════════════════════════════════════════════════╗{C['reset']}")
        print(f"{C['bold']}{C['cyan']}║      TPMS Capture Tool — Anti-Stalking Research             ║{C['reset']}")
        print(f"{C['bold']}{C['cyan']}╚══════════════════════════════════════════════════════════════╝{C['reset']}\n")

        if not self._check_prerequisites():
            log_error("Prerequisites not met — exiting")
            sys.exit(1)

        print()
        log_info(f"Database: {DB_PATH}")
        log_info(f"Monitoring {len(TPMS_PROTOCOLS)} TPMS protocols")
        log_info(f"Device 0 (E4000):  315.000 MHz (North America)")
        log_info(f"Device 1 (R820T):  433.920 MHz (Europe/aftermarket)")
        log_info(f"Status updates every 30 seconds")
        log_info(f"Press Ctrl+C to stop and see summary")
        print()

        # Start both receivers in threads
        t315 = threading.Thread(
            target=self.run_receiver,
            args=(0, 315_000_000, "315MHz"),
            daemon=True,
            name="receiver-315MHz",
        )
        t433 = threading.Thread(
            target=self.run_receiver,
            args=(1, 433_920_000, "433MHz"),
            daemon=True,
            name="receiver-433MHz",
        )

        t315.start()
        log_ok("315 MHz receiver thread started")
        t433.start()
        log_ok("433 MHz receiver thread started")
        print()

        # Main loop: periodic status + keep-alive
        try:
            while self.running:
                time.sleep(1)
                now = time.monotonic()
                if now - self.last_status_time >= 30:
                    self.print_periodic_status()
                    self.last_status_time = now

                    # Check if receivers are still alive
                    for proc in self.processes:
                        if proc.poll() is not None and self.running:
                            log_warn(f"rtl_433 PID {proc.pid} has exited (code {proc.returncode})")
        except KeyboardInterrupt:
            self.shutdown()


def main():
    TPMSCapture().run()


if __name__ == "__main__":
    main()
