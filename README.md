# TPMS Capture

Passive tire pressure monitoring system (TPMS) sensor capture and analysis tool for research into vehicle tracking and anti-stalking countermeasures.

TPMS sensors are federally mandated on all US vehicles since 2007. Each sensor broadcasts a unique, static ID in the clear on 315 MHz (North America) or 433.92 MHz (Europe) with no authentication or encryption. This makes every equipped vehicle passively trackable by anyone with ~$50 in hardware. This project captures and analyzes those broadcasts to quantify the real-world privacy risk.

## Hardware

- 2x RTL-SDR dongles (e.g. Nooelec NESDR) — one per frequency band
- Any antenna that covers 315 MHz and/or 433 MHz (stock antennas work fine for roadside capture)

## Prerequisites

- Linux (tested on Kubuntu)
- [rtl_433](https://github.com/merbanan/rtl_433) built from source
- [uv](https://docs.astral.sh/uv/) package manager
- RTL-SDR kernel driver blacklisted (the tool needs raw USB access):

  ```bash
  echo 'blacklist dvb_usb_rtl28xxu' | sudo tee /etc/modprobe.d/blacklist-rtlsdr.conf
  ```

## Setup

```bash
git clone https://github.com/leakydata/tpms.git
cd tpms
uv sync
```

## Usage

### Capture

Run both dongles simultaneously — device 0 on 315 MHz, device 1 on 433.92 MHz:

```bash
uv run tpms-capture
```

The terminal shows color-coded live output for every decoded signal, SDR status, database writes, and periodic stats. Press `Ctrl+C` to stop and get a session summary with vehicle correlation.

All readings are stored in `tpms_data.db` (SQLite).

### Analysis

```bash
# Full report (overview, repeat visitors, hourly distribution, vehicles, risk)
uv run tpms-analyze

# Individual reports
uv run tpms-analyze repeat     # sensors seen across multiple time windows
uv run tpms-analyze risk       # stalking risk assessment
uv run tpms-analyze hourly     # capture distribution by hour of day
uv run tpms-analyze vehicles   # correlated sensor groups
uv run tpms-analyze csv        # export readings to CSV
```

## Supported Protocols

Decodes 29 TPMS protocols via rtl_433, covering most vehicles on the road:

| Protocol | Vehicles |
| -------- | -------- |
| Schrader | Ford, GM, Chrysler, Subaru, Infiniti, Nissan, Renault, Opel, Saab |
| Toyota / PMV-107J | Toyota, Lexus |
| BMW Gen2-Gen5 | BMW, Mini |
| HUF/Beru, Continental | Audi, VW, BMW |
| Hyundai VDO | Hyundai, Kia |
| Citroen | Citroen, Peugeot |
| Renault | Renault |
| Ford | Ford |
| TRW (OOK + FSK) | Various OEM and aftermarket |
| Steelmate, Jansite, EezTire, AVE | Aftermarket sensors |
| Porsche | Boxster, Cayman |
| Abarth | 124 Spider |
| Elantra2012 | Hyundai Elantra |

## How It Works

1. Two RTL-SDR dongles listen on 315 MHz and 433.92 MHz simultaneously
2. `rtl_433` decodes raw RF into structured JSON (sensor ID, pressure, temperature, battery, signal level)
3. Python ingests the JSON stream, normalizes units, and stores everything in SQLite
4. On shutdown, sensors seen within 30-second windows are correlated into likely vehicle groups (most vehicles have 4 TPMS sensors)
5. The analysis tool identifies repeat visitors — vehicles seen across multiple time windows — demonstrating passive re-identification

## Privacy Implications

This project exists to demonstrate a real and underappreciated privacy risk:

- **Cost of attack**: Under $50 in commodity hardware, free open-source software
- **Skill required**: Minimal — run a script
- **Detectability**: Zero — purely passive RF reception
- **Range**: Roadside capture of passing traffic is trivial
- **Persistence**: Sensor IDs are static for the life of the sensor (typically 5-10 years)
- **Scale**: Multiple stations could build city-wide vehicle movement profiles

### Mitigations That Should Exist

- Rolling/rotating sensor IDs (similar to BLE MAC randomization)
- Encrypted or authenticated TPMS broadcasts
- Reduced transmit power (current range far exceeds safety requirements)
- Regulatory standards mandating TPMS privacy protections

## License

MIT
