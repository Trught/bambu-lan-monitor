# Bambu LAN Monitor

Python 3.12+ LAN discovery and read-only MQTT telemetry for Bambu Lab printers.
One runtime dependency: `paho-mqtt`. All settings are command-line arguments.
English error catalogs are included as plain JSON

## Quick start

```sh
python -m pip install -r requirements.txt
python bambu_monitor.py discover
python bambu_monitor.py monitor --serial YOUR_SERIAL --access-code YOUR_ACCESS_CODE
```

Set an IP explicitly to skip discovery:

```sh
python bambu_monitor.py monitor --ip 192.168.1.123 --serial YOUR_SERIAL --access-code YOUR_ACCESS_CODE
```

`YOUR_SERIAL` and `YOUR_ACCESS_CODE` are placeholders. Obtain the actual values
from your own printer; they are never guessed or fetched from the cloud.
Command-line secrets can be visible in shell history and local process listings.
The application never prints the access code.

## Options

| Option | Command | Purpose |
| --- | --- | --- |
| `--serial SERIAL` | monitor | Required printer serial number |
| `--access-code CODE` | monitor | Required LAN/developer access code |
| `--ip IPv4` | monitor | Printer IP; automatic LAN discovery if omitted |
| `--model MODEL` | monitor | Optional model name for model-specific error descriptions |
| `--sensor-interval SECONDS` | monitor | Sensor snapshot interval, default 5; 0 prints on every report |
| `--cert-file FILE.pem` | monitor | Trust the previously verified printer certificate |
| `--save-cert FILE.pem` | discover | Save the sole discovered TLS candidate's certificate |
| `--passive-seconds SECONDS` | both | Passive discovery duration, default 6 |
| `--active-seconds SECONDS` | both | Standard SSDP query duration, default 2 |
| `--scan-timeout SECONDS` | both | TCP connection timeout, default 0.35 |
| `--workers COUNT` | both | Local scan workers, default 32; maximum 64 |

For a sensor snapshot on each incoming MQTT report:

```sh
python bambu_monitor.py monitor --serial YOUR_SERIAL --access-code YOUR_ACCESS_CODE --sensor-interval 0
```

An interval controls local logging, not the printer's telemetry sampling rate.
The last merged sensor state is repeated even when its values are unchanged.
If no MQTT reports arrive, nothing is printed; individual fields can remain
unchanged or absent in incremental updates.

## Telemetry

- `[STATE]`: print state, progress, remaining time, layers, nozzle/bed current
  and target temperatures, job, speed, AMS status, active slot and filament,
  AMS humidity, HMS and print-error codes.
- `[SENSORS]`: chamber temperature/target, part/aux/chamber/heatbreak/secondary
  aux fans, AMS temperature and drying information, Wi-Fi, door state,
  extruder filament sensor, airduct mode, camera settings and lights.
- `[HMS]` / `[PRINT-ERROR]`: separate codes, bundled English descriptions and
  HMS Wiki links. Reports that clear are logged as `cleared`.

Only fields actually received are displayed. Nested objects are merged into
local state; lists replace earlier lists. Both legacy temperature fields and
newer packed temperature fields are supported, including left/right nozzles.
Legacy fan fields use 0-15 PWM steps, displayed in 10% buckets; `aux2` already
reports a percentage. AMS `humidity_raw` is percent; `humidity` is labeled as
the raw 1-5 index rather than being presented as a percentage.

```text
[MQTT] Connected
[MQTT] Subscribed to device/YOUR_SERIAL/report
[STATE] RUNNING | 42% | 38 min remaining | layer 87/355 | nozzle 220°C→220°C | bed 55°C→55°C
[SENSORS] chamber 36°C | fans part 80%, aux 20%, chamber 40%, heatbreak 100% | WiFi -53 dBm
```

The code `HMS_0503_0000_0003_0027` remains visible as `[HMS-STATUS]` because it
was observed without a display warning during normal printing. This is a local
observation, not an officially confirmed interpretation; check the printer
display if it is unexpected. Other unknown HMS codes remain visible as HMS.

## LAN and MQTT behavior

Discovery listens for Bambu SSDP announcements, then tries a standard SSDP
query. If no printer is found, a bounded parallel TCP 8883 scan runs only
within the selected local subnet, at most a `/24`. Explicit IPs and discovery
replies outside that boundary are rejected. Hostname, locally available
MAC/vendor and TLS metadata are included where available.

Vendor lookup optionally reads an existing Wireshark `manuf`, Nmap prefix or
IEEE OUI database from disk. It never starts those applications, installs them
or calls a vendor API. If no local database is available, vendor is unavailable.

The MQTT client connects to TLS port 8883 as `bblp` and subscribes only to
`device/<SERIAL>/report`. It has no `publish` calls and sends no `pushall`,
printer control, version query or other application command. Standard MQTT
connection, subscription, keepalive and disconnect packets are still used.
The program cannot force a fresh/full report or increase a sensor's physical
sampling rate in this mode.

LAN Only Mode OFF and Developer Mode OFF do not guarantee that third-party
local MQTT authentication is permitted. Availability depends on printer model
and firmware. A valid LAN/developer access code is required; discovery cannot
retrieve it anonymously. Authentication failure is reported without retries
with other credentials. This tool never changes printer modes.

## TLS

Without `--cert-file`, diagnostics explicitly log `CERT_NONE`: traffic is
encrypted, but the printer identity is not verified.

To use a saved certificate:

```sh
python bambu_monitor.py discover --save-cert printer.pem
python bambu_monitor.py monitor --serial YOUR_SERIAL --access-code YOUR_ACCESS_CODE --cert-file printer.pem
```

Verify the device/IP and displayed SHA-256 fingerprint through a trusted path
before trusting the first saved certificate. Discovery does not overwrite a
different existing certificate. A legitimate certificate replacement needs a
new verification. Local certificate files are excluded by `.gitignore`.

## Repository layout

```text
bambu_monitor.py       CLI, LAN discovery, TLS, MQTT and state formatting
data/hms_errors.json   English device_hms and device_error descriptions
data/wiki_links.json   Model-aware HMS Wiki link mapping
requirements.txt       paho-mqtt only
tests/                 Offline tests; no real printer or credentials required
.github/workflows/     Linux/Windows test workflow
THIRD_PARTY_NOTICES.md  ha-bambulab attribution and license
```

The JSON catalogs are already expanded and formatted for editing. They are
loaded directly relative to the script, regardless of the current directory.
Missing/invalid catalogs produce a diagnostic; raw codes still work. The
bundled data is the 2026-09-01 snapshot, not an automatically updated feed.

## Tests

```sh
python -B -m unittest discover -s tests -v
```

Tests cover discovery bounds, incremental state, fan and temperature decoding,
plain JSON error lookup, CLI argument handling and a simulated MQTT session
with exact-topic subscription, authentication failure and no publish operation.

MQTT field mappings and catalogs are derived from
[ha-bambulab](https://github.com/greghesp/ha-bambulab). See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for provenance and license.
