#!/usr/bin/env python3
"""Read-only Bambu Lab LAN discovery and MQTT status monitor.

The MQTT part deliberately exposes no publish operation.  It subscribes to
exactly one topic: device/<serial>/report.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Sequence


MQTT_PORT = 8883
SSDP_GROUP = "239.255.255.250"
SSDP_LISTEN_PORTS = (1990, 2021)
SSDP_SEARCH_PORTS = (1900, 1990, 2021)
SSDP_DEVICE_TYPE = "urn:bambulab-com:device:3dprinter:1"
DEFAULT_PASSIVE_SECONDS = 6.0
DEFAULT_ACTIVE_SECONDS = 2.0
DEFAULT_SCAN_TIMEOUT = 0.35
DEFAULT_TLS_TIMEOUT = 2.0
DEFAULT_WORKERS = 32
DEFAULT_SENSOR_LOG_INTERVAL = 5.0
MAX_SCAN_ADDRESSES = 256
SERIAL_PATTERN = re.compile(r"[A-Za-z0-9_-]{6,64}")
MAC_PATTERN = re.compile(r"(?i)\b([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b")
ERROR_DATA_DIR = Path(__file__).resolve().parent / "data"
HMS_SEVERITY_LEVELS: dict[int, str] = {
    1: "fatal",
    2: "serious",
    3: "common",
    4: "info",
}
HMS_MODULES: dict[int, str] = {
    0x03: "motion controller",
    0x05: "mainboard",
    0x07: "AMS",
    0x08: "toolhead",
    0x0C: "camera",
}
DEFAULT_HMS_WIKI_URL = "https://wiki.bambulab.com/en/hms/home"
SSDP_MODEL_ALIASES = {"N6": "X2D"}
AIRDUCT_MODES = {0: "cooling", 1: "heating", 2: "laser"}
DOOR_OPEN_MASK = 0x00800000
KNOWN_NORMAL_HMS_NOTES = {
    "HMS_0503_0000_0003_0027": (
        "observed informational telemetry status; not treated as a fault; "
        "verify the printer display if unexpected (unconfirmed meaning)"
    ),
}


class BambuMonitorError(RuntimeError):
    """Expected, user-facing application failure."""


@dataclass(frozen=True)
class NetworkContext:
    local_ip: ipaddress.IPv4Address
    interface_name: str | None
    configured_network: ipaddress.IPv4Network
    scan_network: ipaddress.IPv4Network


@dataclass
class CertificateInfo:
    protocol: str | None = None
    cipher: str | None = None
    sha256: str | None = None
    subject: str | None = None
    issuer: str | None = None
    common_name: str | None = None
    sans: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    pem: str | None = None
    error: str | None = None


@dataclass
class Candidate:
    ip: ipaddress.IPv4Address
    port_8883_open: bool = False
    tls: bool = False
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    discovery_headers: dict[str, str] = field(default_factory=dict)
    certificate: CertificateInfo | None = None
    signs: list[str] = field(default_factory=list)
    confidence: str = "low"
    score: int = 0

    @property
    def serial(self) -> str | None:
        value = self.discovery_headers.get("usn")
        return value.strip() if value else None

    @property
    def model(self) -> str | None:
        return self.discovery_headers.get("devmodel.bambu.com")

    @property
    def name(self) -> str | None:
        return self.discovery_headers.get("devname.bambu.com")


@dataclass(frozen=True)
class HMSReport:
    code: str
    severity: str
    module: str
    message: str | None
    wiki_url: str
    normal_status: bool = False
    note: str | None = None


@dataclass(frozen=True)
class PrintErrorReport:
    code: str
    message: str | None


class ErrorCatalog:
    """Load the bundled, uncompressed English HMS/print-error JSON catalogs."""

    def __init__(
        self,
        data_dir: Path = ERROR_DATA_DIR,
        device_model: str | None = None,
    ) -> None:
        model = device_model.upper() if device_model else None
        self.device_model = SSDP_MODEL_ALIASES.get(model, model)
        self.error_data = self._load_json(data_dir / "hms_errors.json")
        self.wiki_data = self._load_json(data_dir / "wiki_links.json")

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        try:
            with path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
            if not isinstance(value, dict):
                raise ValueError("expected a JSON object")
            return value
        except (OSError, UnicodeError, ValueError) as exc:
            log("HMS", f"Could not load {path.name}: {exc}; raw codes remain available")
            return {}

    def _select(self, entries: Any) -> str | None:
        if not isinstance(entries, Mapping):
            return None
        fallback: str | None = None
        for text, models in entries.items():
            if not isinstance(text, str) or not isinstance(models, list):
                continue
            if self.device_model in {str(model).upper() for model in models}:
                return text
            if not models:
                fallback = text
        return fallback

    def lookup(self, error_type: str, code: str) -> str | None:
        catalog = self.error_data.get(error_type, {})
        if not isinstance(catalog, Mapping):
            return None
        return self._select(catalog.get(code.replace("_", "").upper()))

    def wiki_url(self, code: str) -> str:
        path = self._select(self.wiki_data.get(code.replace("_", "").upper()))
        return f"https://wiki.bambulab.com{path}" if path else DEFAULT_HMS_WIKI_URL


def log(tag: str, message: str) -> None:
    print(f"[{tag}] {message}", flush=True)


def configure_console_encoding() -> None:
    """Keep temperature symbols readable in Windows terminals and redirected logs."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (LookupError, OSError):
            pass


def run_command(command: Sequence[str], timeout: float = 3.0) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return ""
    return completed.stdout


def _route_selected_ipv4() -> ipaddress.IPv4Address:
    """Ask the local routing table for an address without sending a packet."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect only selects a route; it does not transmit a datagram.
        sock.connect(("192.0.2.1", 9))
        return ipaddress.IPv4Address(sock.getsockname()[0])
    except OSError:
        # A LAN without a default route can still be useful.  Fall back to the
        # host's configured addresses and choose a non-loopback private IPv4.
        try:
            addresses = socket.getaddrinfo(
                socket.gethostname(), None, socket.AF_INET, socket.SOCK_DGRAM
            )
        except OSError as exc:
            raise BambuMonitorError(
                "Could not determine the primary local IPv4 address."
            ) from exc
        for address in addresses:
            candidate = ipaddress.IPv4Address(address[4][0])
            if not candidate.is_loopback and (candidate.is_private or candidate.is_link_local):
                return candidate
        raise BambuMonitorError("Could not find a non-loopback private IPv4 address.")
    finally:
        sock.close()


def _windows_interface(ip: ipaddress.IPv4Address) -> tuple[int, str | None] | None:
    escaped_ip = str(ip).replace("'", "''")
    script = (
        "Get-NetIPAddress -AddressFamily IPv4 | "
        f"Where-Object {{$_.IPAddress -eq '{escaped_ip}'}} | "
        "Select-Object -First 1 IPAddress,PrefixLength,InterfaceAlias | "
        "ConvertTo-Json -Compress"
    )
    output = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=5.0,
    )
    if output.strip():
        try:
            data = json.loads(output)
            return int(data["PrefixLength"]), data.get("InterfaceAlias")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            pass

    # Get-NetIPAddress can be denied in restricted Windows sessions.  The
    # read-only route table needs no elevation and its numeric columns are not
    # localized, so it is a dependable fallback for the prefix.
    route_output = run_command(["route", "print", "-4"], timeout=3.0)
    prefix = _prefix_from_windows_routes(ip, route_output)
    return (prefix, None) if prefix is not None else None


def _prefix_from_windows_routes(
    ip: ipaddress.IPv4Address, output: str
) -> int | None:
    matches: list[int] = []
    for line in output.splitlines():
        address_tokens = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
        if len(address_tokens) < 3 or str(ip) not in address_tokens[2:]:
            continue
        try:
            network = ipaddress.IPv4Network(
                (address_tokens[0], address_tokens[1]), strict=False
            )
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            continue
        if 0 < network.prefixlen < 32 and ip in network:
            matches.append(network.prefixlen)
    return max(matches) if matches else None


def _linux_interface(ip: ipaddress.IPv4Address) -> tuple[int, str | None] | None:
    output = run_command(["ip", "-j", "-4", "address", "show", "up"], timeout=3.0)
    if not output.strip():
        return None
    try:
        interfaces = json.loads(output)
        for interface in interfaces:
            for address in interface.get("addr_info", []):
                if address.get("local") == str(ip):
                    return int(address["prefixlen"]), interface.get("ifname")
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None
    return None


def get_network_context() -> NetworkContext:
    local_ip = _route_selected_ipv4()
    if not (local_ip.is_private or local_ip.is_link_local):
        raise BambuMonitorError(
            f"Refusing LAN discovery from non-private address {local_ip}."
        )

    interface: tuple[int, str | None] | None
    if platform.system() == "Windows":
        interface = _windows_interface(local_ip)
    else:
        interface = _linux_interface(local_ip)

    if interface is None:
        prefix, interface_name = 24, None
        log("NETWORK", "Netmask lookup failed; using a conservative local /24.")
    else:
        prefix, interface_name = interface

    configured = ipaddress.ip_interface(f"{local_ip}/{prefix}").network
    # Never expand beyond the /24 containing this host.  On a smaller subnet,
    # retain the smaller subnet so no off-link address is scanned.
    scan_network = (
        ipaddress.ip_interface(f"{local_ip}/24").network
        if configured.prefixlen < 24
        else configured
    )
    if scan_network.num_addresses > MAX_SCAN_ADDRESSES:
        raise BambuMonitorError("Internal safety check refused a scan over 256 addresses.")
    return NetworkContext(local_ip, interface_name, configured, scan_network)


def parse_ssdp_packet(data: bytes) -> tuple[str, dict[str, str]]:
    text = data.decode("utf-8", errors="replace")
    lines = text.replace("\r\n", "\n").split("\n")
    first_line = lines[0].strip() if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return first_line, headers


def is_bambu_discovery(first_line: str, headers: Mapping[str, str]) -> bool:
    joined = " ".join(
        [first_line, headers.get("nt", ""), headers.get("st", ""), headers.get("server", "")]
    ).lower()
    return (
        "bambulab" in joined
        or "bambu.com" in joined
        or any(key.endswith(".bambu.com") for key in headers)
    )


def _packet_ip(
    headers: Mapping[str, str], source_ip: str
) -> ipaddress.IPv4Address | None:
    location = headers.get("location", "").strip()
    match = re.search(r"(?:https?://)?(\d{1,3}(?:\.\d{1,3}){3})", location)
    raw = match.group(1) if match else source_ip
    try:
        return ipaddress.IPv4Address(raw)
    except ipaddress.AddressValueError:
        return None


def _make_listener(local_ip: ipaddress.IPv4Address, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", port))
        membership = socket.inet_aton(SSDP_GROUP) + socket.inet_aton(str(local_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


def _collect_udp(
    sockets: Sequence[socket.socket],
    deadline: float,
    network: ipaddress.IPv4Network,
    found: MutableMapping[ipaddress.IPv4Address, dict[str, str]],
) -> None:
    while sockets and time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        readable, _, _ = select.select(list(sockets), [], [], min(0.25, remaining))
        for sock in readable:
            try:
                data, address = sock.recvfrom(65535)
            except (BlockingIOError, OSError):
                continue
            first_line, headers = parse_ssdp_packet(data)
            if not is_bambu_discovery(first_line, headers):
                continue
            device_ip = _packet_ip(headers, address[0])
            if device_ip is None or device_ip not in network:
                log("SAFETY", f"Ignored discovery response outside {network}: {address[0]}")
                continue
            found.setdefault(device_ip, {}).update(headers)


def passive_discovery(
    context: NetworkContext, timeout: float = DEFAULT_PASSIVE_SECONDS
) -> dict[ipaddress.IPv4Address, dict[str, str]]:
    listeners: list[socket.socket] = []
    for port in SSDP_LISTEN_PORTS:
        try:
            listeners.append(_make_listener(context.local_ip, port))
        except OSError as exc:
            log("DISCOVERY", f"Could not listen on UDP {port}: {exc}")
    found: dict[ipaddress.IPv4Address, dict[str, str]] = {}
    try:
        if listeners:
            _collect_udp(
                listeners, time.monotonic() + max(0.0, timeout), context.scan_network, found
            )
    finally:
        for sock in listeners:
            sock.close()
    return found


def active_ssdp_discovery(
    context: NetworkContext, timeout: float = DEFAULT_ACTIVE_SECONDS
) -> dict[ipaddress.IPv4Address, dict[str, str]]:
    query = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_GROUP}:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        f"ST: {SSDP_DEVICE_TYPE}\r\n\r\n"
    ).encode("ascii")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(str(context.local_ip)))
    sock.bind((str(context.local_ip), 0))
    sock.setblocking(False)
    found: dict[ipaddress.IPv4Address, dict[str, str]] = {}
    try:
        for port in SSDP_SEARCH_PORTS:
            try:
                sock.sendto(query, (SSDP_GROUP, port))
            except OSError as exc:
                log("DISCOVERY", f"SSDP query to UDP {port} failed: {exc}")
        _collect_udp([sock], time.monotonic() + max(0.0, timeout), context.scan_network, found)
    finally:
        sock.close()
    return found


def tcp_port_open(ip: ipaddress.IPv4Address, timeout: float) -> bool:
    try:
        with socket.create_connection((str(ip), MQTT_PORT), timeout=timeout):
            return True
    except OSError:
        return False


def scan_port_8883(
    context: NetworkContext,
    timeout: float = DEFAULT_SCAN_TIMEOUT,
    workers: int = DEFAULT_WORKERS,
) -> list[ipaddress.IPv4Address]:
    if context.scan_network.num_addresses > MAX_SCAN_ADDRESSES:
        raise BambuMonitorError("Refusing to scan more than one /24.")
    targets = [ip for ip in context.scan_network.hosts() if ip != context.local_ip]
    open_hosts: list[ipaddress.IPv4Address] = []
    safe_workers = max(1, min(int(workers), 64, len(targets) or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=safe_workers) as executor:
        futures = {executor.submit(tcp_port_open, ip, timeout): ip for ip in targets}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    log("FOUND", f"{ip}:{MQTT_PORT}")
                    open_hosts.append(ip)
            except OSError:
                continue
    return sorted(open_hosts)


def _format_x509_name(name: Iterable[Iterable[tuple[str, str]]]) -> str | None:
    parts: list[str] = []
    for relative_name in name:
        for key, value in relative_name:
            parts.append(f"{key}={value}")
    return ", ".join(parts) or None


def _common_name(name: Iterable[Iterable[tuple[str, str]]]) -> str | None:
    for relative_name in name:
        for key, value in relative_name:
            if key.lower() == "commonname":
                return value
    return None


def decode_der_certificate(der: bytes) -> tuple[dict[str, Any], str]:
    pem = ssl.DER_cert_to_PEM_cert(der)
    path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", suffix=".pem", delete=False
        ) as handle:
            handle.write(pem)
            path = handle.name
        # CPython exposes no public standard-library DER metadata decoder.  This
        # private helper is used only for display; TLS security never relies on it.
        decoder = getattr(ssl._ssl, "_test_decode_cert", None)  # type: ignore[attr-defined]
        decoded = decoder(path) if decoder is not None else {}
        return decoded, pem
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def inspect_tls_certificate(
    ip: ipaddress.IPv4Address,
    timeout: float = DEFAULT_TLS_TIMEOUT,
    server_name: str | None = None,
) -> CertificateInfo:
    info = CertificateInfo()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((str(ip), MQTT_PORT), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with context.wrap_socket(raw, server_hostname=server_name) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                if not der:
                    raise ssl.SSLError("peer did not provide a certificate")
                info.protocol = tls_sock.version()
                selected_cipher = tls_sock.cipher()
                info.cipher = selected_cipher[0] if selected_cipher else None
        decoded, pem = decode_der_certificate(der)
        info.pem = pem
        info.sha256 = hashlib.sha256(der).hexdigest().upper()
        subject = decoded.get("subject", ())
        issuer = decoded.get("issuer", ())
        info.subject = _format_x509_name(subject)
        info.issuer = _format_x509_name(issuer)
        info.common_name = _common_name(subject)
        info.sans = [f"{kind}:{value}" for kind, value in decoded.get("subjectAltName", ())]
        info.not_before = decoded.get("notBefore")
        info.not_after = decoded.get("notAfter")
    except (OSError, ssl.SSLError, ValueError) as exc:
        info.error = str(exc)
    return info


def reverse_hostname(ip: ipaddress.IPv4Address) -> str | None:
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(socket.gethostbyaddr, str(ip))
    try:
        return future.result(timeout=1.5)[0]
    except (concurrent.futures.TimeoutError, OSError):
        future.cancel()
        return None
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def get_mac_address(ip: ipaddress.IPv4Address) -> str | None:
    if os.name == "nt":
        output = run_command(["arp", "-a", str(ip)], timeout=2.0)
    else:
        output = run_command(["ip", "neigh", "show", str(ip)], timeout=2.0)
        if not output:
            output = run_command(["arp", "-n", str(ip)], timeout=2.0)
    match = MAC_PATTERN.search(output)
    return match.group(1).upper().replace("-", ":") if match else None


def lookup_local_vendor(mac: str | None) -> str | None:
    """Read optional local OUI files; never launch or require Wireshark/Nmap."""
    if not mac:
        return None
    prefix_colon = mac.upper()[:8]
    prefix_plain = prefix_colon.replace(":", "")
    prefix_hyphen = prefix_colon.replace(":", "-")
    candidates = [
        Path("/usr/share/wireshark/manuf"),
        Path("/usr/share/nmap/nmap-mac-prefixes"),
        Path("/usr/share/ieee-data/oui.txt"),
        Path("/usr/share/misc/oui.txt"),
    ]
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(Path(program_files) / "Wireshark" / "manuf")

    for path in candidates:
        if not path.is_file():
            continue
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    stripped = line.strip()
                    upper = stripped.upper()
                    if (
                        upper.startswith(prefix_colon)
                        or upper.startswith(prefix_plain)
                        or upper.startswith(prefix_hyphen)
                    ):
                        if "(HEX)" in upper:
                            return stripped.split("(hex)", 1)[-1].strip()
                        fields = stripped.split(maxsplit=1)
                        return fields[1].strip() if len(fields) == 2 else None
        except OSError:
            continue
    return None


def score_candidate(candidate: Candidate) -> None:
    score = 0
    signs: list[str] = []
    headers = candidate.discovery_headers
    if headers:
        first_values = " ".join(headers.values()).lower()
        if "bambulab" in first_values or any(key.endswith(".bambu.com") for key in headers):
            score += 45
            signs.append("Bambu SSDP headers")
        if candidate.model:
            score += 20
            signs.append(f"model {candidate.model}")
        if candidate.serial:
            score += 5
            signs.append("serial from SSDP")
    if candidate.port_8883_open:
        score += 15
        signs.append("TCP 8883 open")
    cert = candidate.certificate
    if cert and cert.sha256:
        score += 5
        cert_text = " ".join(
            filter(None, [cert.subject, cert.issuer, cert.common_name, " ".join(cert.sans)])
        ).lower()
        if "bambu" in cert_text or "bbl" in cert_text:
            score += 25
            signs.append("Bambu/BBL certificate identity")
        if candidate.serial and cert.common_name and candidate.serial.lower() in cert.common_name.lower():
            score += 10
            signs.append("certificate CN matches SSDP serial")
    if candidate.vendor and "bambu" in candidate.vendor.lower():
        score += 25
        signs.append("Bambu MAC vendor")
    if candidate.hostname and "bambu" in candidate.hostname.lower():
        score += 10
        signs.append("Bambu hostname")
    candidate.score = score
    candidate.signs = signs
    candidate.confidence = "high" if score >= 60 else "medium" if score >= 35 else "low"


def enrich_candidate(candidate: Candidate) -> Candidate:
    if not candidate.port_8883_open:
        candidate.port_8883_open = tcp_port_open(candidate.ip, DEFAULT_SCAN_TIMEOUT)
    candidate.hostname = reverse_hostname(candidate.ip)
    candidate.mac = get_mac_address(candidate.ip)
    candidate.vendor = lookup_local_vendor(candidate.mac)
    if candidate.port_8883_open:
        candidate.certificate = inspect_tls_certificate(
            candidate.ip, server_name=candidate.serial
        )
        candidate.tls = bool(candidate.certificate.sha256)
        if candidate.tls:
            log("TLS", f"Certificate received from {candidate.ip}:{MQTT_PORT}")
    score_candidate(candidate)
    return candidate


def discover_candidates(
    context: NetworkContext,
    passive_seconds: float = DEFAULT_PASSIVE_SECONDS,
    active_seconds: float = DEFAULT_ACTIVE_SECONDS,
    scan_timeout: float = DEFAULT_SCAN_TIMEOUT,
    workers: int = DEFAULT_WORKERS,
) -> list[Candidate]:
    log(
        "DISCOVERY",
        f"Local IPv4 {context.local_ip}; scan boundary {context.scan_network}",
    )
    log("DISCOVERY", "Listening for Bambu SSDP announcements...")
    discovered = passive_discovery(context, passive_seconds)
    if not discovered:
        log("DISCOVERY", "No passive announcement; sending a standard SSDP search...")
        discovered = active_ssdp_discovery(context, active_seconds)

    candidates: dict[ipaddress.IPv4Address, Candidate] = {
        ip: Candidate(ip=ip, discovery_headers=dict(headers))
        for ip, headers in discovered.items()
    }
    if discovered:
        for ip in sorted(discovered):
            log("FOUND", f"Bambu SSDP response from {ip}")
    else:
        log(
            "DISCOVERY",
            f"SSDP found nothing; scanning only {context.scan_network} for TCP {MQTT_PORT}...",
        )
        for ip in scan_port_8883(context, scan_timeout, workers):
            candidates.setdefault(ip, Candidate(ip=ip, port_8883_open=True))

    if not candidates:
        return []
    enriched: list[Candidate] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(8, len(candidates))
    ) as executor:
        futures = [executor.submit(enrich_candidate, candidate) for candidate in candidates.values()]
        for future in concurrent.futures.as_completed(futures):
            enriched.append(future.result())
    return sorted(enriched, key=lambda item: (-item.score, int(item.ip)))


def print_candidate(candidate: Candidate) -> None:
    heading = (
        "Possible Bambu printer found"
        if candidate.confidence in {"high", "medium"}
        else "TLS/MQTT candidate found"
    )
    print(f"\n{heading}")
    print(f"IP: {candidate.ip}")
    print(f"Port {MQTT_PORT}: {'open' if candidate.port_8883_open else 'closed'}")
    print(f"TLS: {'yes' if candidate.tls else 'no'}")
    print(f"Hostname: {candidate.hostname or 'unavailable'}")
    print(f"MAC: {candidate.mac or 'unavailable'}")
    print(f"Vendor: {candidate.vendor or 'unavailable (no local OUI database match)'}")
    if candidate.name:
        print(f"Discovery name: {candidate.name}")
    if candidate.model:
        print(f"Discovery model: {candidate.model}")
    if candidate.serial:
        print(f"Discovery serial: {candidate.serial}")
    cert = candidate.certificate
    if cert:
        print(f"Certificate CN: {cert.common_name or 'unavailable'}")
        print(f"Certificate SAN: {', '.join(cert.sans) if cert.sans else 'none'}")
        print(f"Certificate issuer: {cert.issuer or 'unavailable'}")
        print(f"Certificate SHA-256: {cert.sha256 or 'unavailable'}")
        print(f"TLS protocol/cipher: {cert.protocol or '?'} / {cert.cipher or '?'}")
        if cert.error:
            print(f"TLS diagnostic error: {cert.error}")
    print(f"Signs: {', '.join(candidate.signs) if candidate.signs else 'TCP 8883 only'}")
    print(f"Confidence: {candidate.confidence}")


def save_candidate_certificate(candidate: Candidate, destination: Path) -> Path:
    cert = candidate.certificate
    if not cert or not cert.pem:
        raise BambuMonitorError(f"No TLS certificate was received from {candidate.ip}.")
    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        existing = destination.read_text(encoding="ascii")
        if existing != cert.pem:
            raise BambuMonitorError(
                f"Refusing to overwrite a different certificate at {destination}."
            )
        return destination
    destination.write_text(cert.pem, encoding="ascii", newline="\n")
    return destination




def validate_serial(serial: str) -> str:
    if not SERIAL_PATTERN.fullmatch(serial):
        raise BambuMonitorError(
            "--serial must contain 6-64 letters, digits, underscores or hyphens."
        )
    return serial


def recursive_merge(target: MutableMapping[str, Any], update: Mapping[str, Any]) -> None:
    for key, value in update.items():
        current = target.get(key)
        if isinstance(current, MutableMapping) and isinstance(value, Mapping):
            recursive_merge(current, value)
        elif isinstance(value, Mapping):
            nested: dict[str, Any] = {}
            recursive_merge(nested, value)
            target[key] = nested
        else:
            target[key] = value


def _present(value: Any) -> bool:
    return value is not None and value != ""


def _first(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if _present(value):
            return value
    return None


def _temperature(value: Any) -> str | None:
    if not _present(value):
        return None
    try:
        return f"{float(value):.0f}°C"
    except (TypeError, ValueError):
        return f"{value}°C"


def _active_ams_tray(print_state: Mapping[str, Any]) -> tuple[str | None, Mapping[str, Any] | None]:
    ams_state = print_state.get("ams")
    if not isinstance(ams_state, Mapping):
        return None, None
    tray_now = _first(ams_state, "tray_now", "tray_tar")
    if not _present(tray_now):
        return None, None
    tray_text = str(tray_now)
    try:
        global_index = int(tray_text)
    except ValueError:
        return tray_text, None
    if global_index in {254, 255}:
        virtual = ams_state.get("vt_tray")
        return "external", virtual if isinstance(virtual, Mapping) else None
    unit_id, slot_id = divmod(global_index, 4)
    units = ams_state.get("ams", [])
    if isinstance(units, list):
        for unit in units:
            if not isinstance(unit, Mapping) or str(unit.get("id")) != str(unit_id):
                continue
            trays = unit.get("tray", [])
            if isinstance(trays, list):
                for tray in trays:
                    if isinstance(tray, Mapping) and str(tray.get("id")) == str(slot_id):
                        return f"AMS {unit_id + 1} slot {slot_id + 1}", tray
    return f"AMS {unit_id + 1} slot {slot_id + 1}", None


def _filament_description(tray: Mapping[str, Any] | None) -> str | None:
    if not tray:
        return None
    material = _first(tray, "tray_type", "tray_sub_brands", "tray_info_idx")
    color = _first(tray, "tray_color", "color")
    pieces: list[str] = []
    if _present(material):
        pieces.append(str(material))
    if _present(color):
        color_text = str(color).lstrip("#")
        if re.fullmatch(r"[0-9A-Fa-f]{8}", color_text):
            color_text = color_text[:6]
        pieces.append(f"#{color_text}" if re.fullmatch(r"[0-9A-Fa-f]{6}", color_text) else str(color))
    return " ".join(pieces) or None


def _integer(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        if isinstance(value, str):
            text = value.strip()
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        return int(value)
    except (TypeError, ValueError):
        return None


def _nested_mapping(mapping: Mapping[str, Any], *keys: str) -> Mapping[str, Any] | None:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current if isinstance(current, Mapping) else None


def _packed_temperature(value: Any) -> tuple[int, int] | None:
    """Decode newer Bambu low-word/current, high-word/target temperatures."""
    packed = _integer(value)
    if packed is None or packed < 0:
        return None
    return packed & 0xFFFF, (packed >> 16) & 0xFFFF


def _bed_temperatures(print_state: Mapping[str, Any]) -> tuple[Any, Any]:
    bed_info = _nested_mapping(print_state, "device", "bed", "info")
    if bed_info is not None and "temp" in bed_info:
        packed = _packed_temperature(bed_info.get("temp"))
        if packed is not None:
            return packed
    return (
        _first(print_state, "bed_temper", "bed_temp"),
        _first(print_state, "bed_target_temper", "bed_target"),
    )


def _chamber_temperatures(print_state: Mapping[str, Any]) -> tuple[Any, Any]:
    chamber_info = _nested_mapping(print_state, "device", "ctc", "info")
    if chamber_info is not None and "temp" in chamber_info:
        packed = _packed_temperature(chamber_info.get("temp"))
        if packed is not None:
            return packed
    return (
        _first(print_state, "chamber_temper", "chamber_temp"),
        _first(print_state, "chamber_target_temper", "chamber_target_temp"),
    )


def _nozzle_temperature_descriptions(print_state: Mapping[str, Any]) -> list[str]:
    extruder = _nested_mapping(print_state, "device", "extruder")
    raw_entries = extruder.get("info") if extruder is not None else None
    readings: list[tuple[int, tuple[int, int]]] = []
    if isinstance(raw_entries, list):
        for entry in raw_entries:
            if not isinstance(entry, Mapping):
                continue
            nozzle_id = _integer(entry.get("id"))
            packed = _packed_temperature(entry.get("temp"))
            if nozzle_id in {0, 1} and packed is not None:
                readings.append((nozzle_id, packed))
    if readings:
        dual = len({nozzle_id for nozzle_id, _pair in readings}) > 1
        descriptions: list[str] = []
        for nozzle_id, (current, target) in sorted(readings):
            label = "nozzle"
            if dual:
                label += " R" if nozzle_id == 0 else " L"
            text = f"{label} {_temperature(current)}"
            target_text = _temperature(target)
            if target_text:
                text += f"→{target_text}"
            descriptions.append(text)
        return descriptions

    current = _temperature(_first(print_state, "nozzle_temper", "nozzle_temp"))
    target = _temperature(_first(print_state, "nozzle_target_temper", "nozzle_target"))
    if not current:
        return []
    return [f"nozzle {current}" + (f"→{target}" if target else "")]


def format_hms_code(attr: Any, code: Any) -> str | None:
    attr_int = _integer(attr)
    code_int = _integer(code)
    if not attr_int or not code_int or attr_int < 0 or code_int < 0:
        return None
    return (
        f"HMS_{(attr_int >> 16) & 0xFFFF:04X}_{attr_int & 0xFFFF:04X}_"
        f"{(code_int >> 16) & 0xFFFF:04X}_{code_int & 0xFFFF:04X}"
    )


def format_print_error_code(value: Any) -> str | None:
    error_int = _integer(value)
    if not error_int or error_int < 0:
        return None
    hexadecimal = f"{error_int & 0xFFFFFFFF:08X}"
    return f"{hexadecimal[:4]}_{hexadecimal[4:]}"


def hms_reports(
    print_state: Mapping[str, Any], catalog: ErrorCatalog | None = None
) -> list[HMSReport]:
    raw_hms = print_state.get("hms")
    if not isinstance(raw_hms, list):
        return []
    reports: list[HMSReport] = []
    seen: set[str] = set()
    for item in raw_hms:
        if not isinstance(item, Mapping):
            continue
        attr = _integer(item.get("attr"))
        code = _integer(item.get("code"))
        formatted = format_hms_code(attr, code)
        if formatted is None or formatted in seen or attr is None or code is None:
            continue
        seen.add(formatted)
        catalog_key = formatted.removeprefix("HMS_")
        status_note = KNOWN_NORMAL_HMS_NOTES.get(formatted)
        reports.append(
            HMSReport(
                code=formatted,
                severity=HMS_SEVERITY_LEVELS.get((code >> 16) & 0xFFFF, "unknown"),
                module=HMS_MODULES.get((attr >> 24) & 0xFF, "unknown"),
                message=catalog.lookup("device_hms", catalog_key) if catalog else None,
                wiki_url=catalog.wiki_url(catalog_key) if catalog else DEFAULT_HMS_WIKI_URL,
                normal_status=status_note is not None,
                note=status_note,
            )
        )
    return reports


def print_error_report(
    print_state: Mapping[str, Any], catalog: ErrorCatalog | None = None
) -> PrintErrorReport | None:
    formatted = format_print_error_code(print_state.get("print_error"))
    if formatted is None:
        return None
    return PrintErrorReport(
        code=formatted,
        message=catalog.lookup("device_error", formatted) if catalog else None,
    )


def _ams_label(raw_id: Any) -> str:
    unit_id = _integer(raw_id)
    if unit_id is None:
        return f"AMS {raw_id}"
    if unit_id >= 128:
        return f"AMS HT {unit_id - 127}"
    return f"AMS {unit_id + 1}"


def _number_in_range(value: Any, minimum: float, maximum: float) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if minimum <= number <= maximum else None


def _format_decimal(value: float) -> str:
    return f"{value:.0f}" if value.is_integer() else f"{value:g}"


def ams_humidity_descriptions(print_state: Mapping[str, Any]) -> list[str]:
    """Return real relative humidity when available, otherwise the 1-5 index."""
    ams_state = print_state.get("ams")
    if not isinstance(ams_state, Mapping):
        return []
    units = ams_state.get("ams")
    if not isinstance(units, list):
        return []
    descriptions: list[str] = []
    for unit in units:
        if not isinstance(unit, Mapping):
            continue
        humidity = _number_in_range(unit.get("humidity_raw"), 1, 100)
        humidity_index = _number_in_range(unit.get("humidity"), 1, 5)
        if humidity is None and humidity_index is None:
            continue
        text = f"{_ams_label(unit.get('id', '?'))} humidity"
        if humidity is not None:
            text += f" {_format_decimal(humidity)}%"
            if humidity_index is not None:
                text += f" (index {_format_decimal(humidity_index)}/5)"
        else:
            assert humidity_index is not None
            text += f" index {_format_decimal(humidity_index)}/5"
        descriptions.append(text)
    return descriptions


def fan_percentage(raw_speed: Any) -> int | None:
    """Convert the printer's legacy 0-15 fan PWM steps to 10% buckets."""
    if isinstance(raw_speed, bool):
        return None
    speed = _integer(raw_speed)
    if speed is None or not 0 <= speed <= 15:
        return None
    if speed == 0:
        return 0
    return min(100, math.ceil(((speed / 15) * 100) / 10) * 10)


def fan_descriptions(print_state: Mapping[str, Any]) -> list[str]:
    descriptions: list[str] = []
    fan_fields = (
        ("part", "cooling_fan_speed"),
        ("aux", "big_fan1_speed"),
        ("chamber", "big_fan2_speed"),
        ("heatbreak", "heatbreak_fan_speed"),
    )
    for label, field_name in fan_fields:
        if field_name not in print_state:
            continue
        percentage = fan_percentage(print_state.get(field_name))
        if percentage is not None:
            descriptions.append(f"{label} {percentage}%")

    airduct = _nested_mapping(print_state, "device", "airduct")
    raw_parts = airduct.get("parts") if airduct is not None else None
    if isinstance(raw_parts, list):
        for part in raw_parts:
            if not isinstance(part, Mapping) or _integer(part.get("id")) != 160:
                continue
            percentage = _number_in_range(part.get("state"), 0, 100)
            if percentage is not None:
                descriptions.append(f"aux2 {_format_decimal(percentage)}%")
            break
    return descriptions


def ams_environment_descriptions(print_state: Mapping[str, Any]) -> list[str]:
    ams_state = print_state.get("ams")
    if not isinstance(ams_state, Mapping):
        return []
    units = ams_state.get("ams")
    if not isinstance(units, list):
        return []

    descriptions: list[str] = []
    for unit in units:
        if not isinstance(unit, Mapping):
            continue
        details: list[str] = []
        temperature = _number_in_range(unit.get("temp"), 0, 100)
        if temperature is not None:
            details.append(f"{_format_decimal(temperature)}°C")

        dry_time = _number_in_range(unit.get("dry_time"), 1, 1_000_000)
        if dry_time is not None:
            drying = f"drying {_format_decimal(dry_time)} min left"
            dry_setting = unit.get("dry_setting")
            if isinstance(dry_setting, Mapping):
                settings: list[str] = []
                dry_temperature = _number_in_range(
                    dry_setting.get("dry_temperature"), 1, 100
                )
                dry_duration = _number_in_range(
                    dry_setting.get("dry_duration"), 1, 10_000
                )
                dry_filament = dry_setting.get("dry_filament")
                if dry_temperature is not None:
                    settings.append(f"{_format_decimal(dry_temperature)}°C")
                if dry_duration is not None:
                    settings.append(f"{_format_decimal(dry_duration)} h")
                if _present(dry_filament):
                    settings.append(str(dry_filament))
                if settings:
                    drying += f" ({', '.join(settings)})"
            details.append(drying)
        if details:
            descriptions.append(f"{_ams_label(unit.get('id', '?'))} {', '.join(details)}")
    return descriptions


def _wifi_description(print_state: Mapping[str, Any]) -> str | None:
    value = print_state.get("wifi_signal")
    if not _present(value):
        return None
    match = re.fullmatch(r"\s*(-?\d+)\s*(?:dBm)?\s*", str(value), re.IGNORECASE)
    return f"WiFi {match.group(1)} dBm" if match else f"WiFi {value}"


def _door_description(print_state: Mapping[str, Any]) -> str | None:
    flags: int | None = None
    stat = print_state.get("stat")
    if _present(stat):
        try:
            flags = int(str(stat), 16) if isinstance(stat, str) else int(stat)
        except (TypeError, ValueError):
            flags = None
    elif "home_flag" in print_state:
        flags = _integer(print_state.get("home_flag"))
    if flags is None:
        return None
    return "door open" if flags & DOOR_OPEN_MASK else "door closed"


def _camera_description(print_state: Mapping[str, Any]) -> str | None:
    camera = print_state.get("ipcam")
    if not isinstance(camera, Mapping):
        return None
    values: list[str] = []
    for label, key in (("recording", "ipcam_record"), ("timelapse", "timelapse")):
        value = camera.get(key)
        if _present(value):
            values.append(f"{label} {value}")
    resolution = camera.get("resolution")
    if _present(resolution):
        values.append(str(resolution))
    return "camera " + ", ".join(values) if values else None


def _lights_description(print_state: Mapping[str, Any]) -> str | None:
    lights = print_state.get("lights_report")
    if not isinstance(lights, list):
        return None
    values: list[str] = []
    for light in lights:
        if not isinstance(light, Mapping):
            continue
        node = light.get("node")
        mode = light.get("mode")
        if _present(node) and _present(mode):
            values.append(f"{node} {mode}")
    return "lights " + ", ".join(values) if values else None


def sensor_summary(state: Mapping[str, Any]) -> str:
    """Summarize read-only environmental and device telemetry."""
    raw_print = state.get("print", state)
    print_state = raw_print if isinstance(raw_print, Mapping) else {}
    parts: list[str] = []

    chamber, chamber_target = _chamber_temperatures(print_state)
    chamber_text = _temperature(chamber)
    target_text = _temperature(chamber_target)
    if chamber_text:
        parts.append(
            f"chamber {chamber_text}" + (f"→{target_text}" if target_text else "")
        )

    fans = fan_descriptions(print_state)
    if fans:
        parts.append("fans " + ", ".join(fans))
    parts.extend(ams_environment_descriptions(print_state))

    for description in (
        _wifi_description(print_state),
        _door_description(print_state),
    ):
        if description:
            parts.append(description)

    if "hw_switch_state" in print_state:
        filament_state = _integer(print_state.get("hw_switch_state"))
        if filament_state is not None:
            parts.append(
                "extruder filament present"
                if bool(filament_state)
                else "extruder filament absent"
            )

    airduct = _nested_mapping(print_state, "device", "airduct")
    if airduct is not None and "modeCur" in airduct:
        mode = _integer(airduct.get("modeCur"))
        if mode is not None:
            parts.append(f"airduct {AIRDUCT_MODES.get(mode, mode)}")

    for description in (
        _camera_description(print_state),
        _lights_description(print_state),
    ):
        if description:
            parts.append(description)
    return " | ".join(parts)


def state_summary(state: Mapping[str, Any]) -> str:
    raw_print = state.get("print", state)
    print_state = raw_print if isinstance(raw_print, Mapping) else {}
    parts: list[str] = []

    gcode_state = _first(print_state, "gcode_state", "state")
    parts.append(str(gcode_state or "UNKNOWN"))
    percent = _first(print_state, "mc_percent", "percent", "progress")
    if _present(percent):
        parts.append(f"{percent}%")
    remaining = _first(print_state, "mc_remaining_time", "remaining_time")
    if _present(remaining):
        parts.append(f"{remaining} min remaining")

    layer = _first(print_state, "layer_num", "current_layer")
    total_layers = _first(print_state, "total_layer_num", "total_layers")
    if _present(layer) or _present(total_layers):
        layer_text = str(layer) if _present(layer) else "?"
        total_text = str(total_layers) if _present(total_layers) else "?"
        parts.append(f"layer {layer_text}/{total_text}")

    parts.extend(_nozzle_temperature_descriptions(print_state))
    bed_value, bed_target_value = _bed_temperatures(print_state)
    bed = _temperature(bed_value)
    bed_target = _temperature(bed_target_value)
    if bed:
        parts.append(f"bed {bed}" + (f"→{bed_target}" if bed_target else ""))

    job = _first(print_state, "subtask_name", "gcode_file", "file", "project_name")
    if _present(job):
        parts.append(f"job {job}")
    speed_percent = _first(print_state, "spd_mag", "speed_percent")
    speed_level = _first(print_state, "spd_lvl", "speed_level")
    if _present(speed_percent) or _present(speed_level):
        speed = f"speed {speed_percent}%" if _present(speed_percent) else "speed"
        if _present(speed_level):
            speed += f" (level {speed_level})"
        parts.append(speed)

    ams_status = _first(print_state, "ams_status", "ams_status_main", "ams_status_sub")
    ams_state = print_state.get("ams")
    if isinstance(ams_state, Mapping):
        ams_status = ams_status or _first(
            ams_state, "ams_status", "status", "ams_status_main", "ams_status_sub"
        )
    if _present(ams_status):
        parts.append(f"AMS status {ams_status}")
    parts.extend(ams_humidity_descriptions(print_state))
    slot, tray = _active_ams_tray(print_state)
    if slot:
        filament = _filament_description(tray)
        parts.append(slot + (f" {filament}" if filament else ""))

    reports = hms_reports(print_state)
    hms_statuses = [report.code for report in reports if report.normal_status]
    hms_faults = [report.code for report in reports if not report.normal_status]
    if hms_statuses:
        parts.append("HMS status " + ",".join(hms_statuses) + " (informational)")
    if hms_faults:
        parts.append("HMS " + ",".join(hms_faults))
    print_error = print_error_report(print_state)
    if print_error:
        parts.append(f"print error {print_error.code}")
    return " | ".join(parts)


def _pinned_ssl_context(cert_file: Path) -> ssl.SSLContext:
    path = cert_file.expanduser().resolve()
    if not path.is_file():
        raise BambuMonitorError(f"Pinned certificate file does not exist: {path}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        context.load_verify_locations(cafile=str(path))
    except ssl.SSLError as exc:
        raise BambuMonitorError(f"Could not load pinned certificate {path}: {exc}") from exc
    partial_chain = getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
    if partial_chain:
        context.verify_flags |= partial_chain
    return context


class ReadOnlyMonitor:
    def __init__(
        self,
        host: ipaddress.IPv4Address,
        serial: str,
        access_code: str,
        cert_file: Path | None,
        device_model: str | None = None,
        sensor_interval: float = DEFAULT_SENSOR_LOG_INTERVAL,
    ) -> None:
        self.host = host
        self.serial = validate_serial(serial)
        self.access_code = access_code
        self.cert_file = cert_file
        self.topic = f"device/{self.serial}/report"
        self.state: dict[str, Any] = {}
        self.last_summary: str | None = None
        self.last_sensor_summary: str | None = None
        self.last_sensor_log_time = 0.0
        self.sensor_interval = sensor_interval
        self.error_catalog = ErrorCatalog(device_model=device_model)
        self.last_hms_state: dict[str, bool] = {}
        self.last_print_error_code: str | None = None
        self.authentication_failed = threading.Event()
        self.subscription_failed = threading.Event()

    def log_error_changes(self) -> None:
        raw_print = self.state.get("print", self.state)
        print_state = raw_print if isinstance(raw_print, Mapping) else {}
        reports = hms_reports(print_state, self.error_catalog)
        active = {report.code: report.normal_status for report in reports}
        if active != self.last_hms_state:
            for code, informational in self.last_hms_state.items():
                if code not in active:
                    log("HMS-STATUS" if informational else "HMS", f"{code} cleared")
            for report in reports:
                if self.last_hms_state.get(report.code) == report.normal_status:
                    continue
                if report.normal_status:
                    log("HMS-STATUS", f"{report.code} | {report.note}")
                else:
                    details = [
                        report.code,
                        f"severity {report.severity}",
                        f"module {report.module}",
                        report.message or "unknown HMS code",
                        report.wiki_url,
                    ]
                    log("HMS", " | ".join(details))
            self.last_hms_state = active

        error = print_error_report(print_state, self.error_catalog)
        code = error.code if error else None
        if code != self.last_print_error_code:
            if error:
                log("PRINT-ERROR", f"{error.code} | {error.message or 'unknown error'}")
            elif self.last_print_error_code:
                log("PRINT-ERROR", f"{self.last_print_error_code} cleared")
            self.last_print_error_code = code

    def process_report(self, update: Mapping[str, Any]) -> None:
        """Merge each report; periodically display the latest sensor snapshot."""
        recursive_merge(self.state, update)
        self.log_error_changes()
        summary = state_summary(self.state)
        if summary != self.last_summary:
            log("STATE", summary)
            self.last_summary = summary
        sensors = sensor_summary(self.state)
        now = time.monotonic()
        if sensors and (
            self.last_sensor_summary is None
            or now - self.last_sensor_log_time >= self.sensor_interval
        ):
            log("SENSORS", sensors)
            self.last_sensor_summary = sensors
            self.last_sensor_log_time = now

    def run(self) -> int:
        try:
            import paho.mqtt.client as mqtt
        except ImportError as exc:
            raise BambuMonitorError(
                "paho-mqtt is not installed. Run: python -m pip install -r requirements.txt"
            ) from exc

        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"bambu-readonly-{uuid.uuid4().hex[:12]}",
            protocol=mqtt.MQTTv311,
            reconnect_on_failure=False,
        )
        client.suppress_exceptions = True
        client.username_pw_set("bblp", self.access_code)
        if self.cert_file:
            client.tls_set_context(_pinned_ssl_context(self.cert_file))
            log("TLS", f"Pinned certificate trust enabled: {self.cert_file}")
        else:
            insecure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            insecure_context.check_hostname = False
            insecure_context.verify_mode = ssl.CERT_NONE
            client.tls_set_context(insecure_context)
            log(
                "TLS",
                "WARNING: diagnostic mode uses CERT_NONE; the broker identity is not verified.",
            )

        def on_connect(
            callback_client: Any,
            _userdata: Any,
            _flags: Any,
            reason_code: Any,
            _properties: Any,
        ) -> None:
            if reason_code == 0:
                log("MQTT", "Connected")
                result, _message_id = callback_client.subscribe(self.topic, qos=0)
                if result != mqtt.MQTT_ERR_SUCCESS:
                    self.subscription_failed.set()
                    log("MQTT", f"Subscription could not be queued: {mqtt.error_string(result)}")
                    callback_client.disconnect()
                return
            reason = str(reason_code)
            reason_lower = reason.lower()
            if any(
                marker in reason_lower
                for marker in ("author", "credential", "password", "user name", "username")
            ):
                self.authentication_failed.set()
                print("MQTT authentication failed.")
                print("A valid Bambu LAN/dev access code is required.")
            else:
                log("MQTT", f"Connection refused: {reason}")
            callback_client.disconnect()

        def on_subscribe(
            callback_client: Any,
            _userdata: Any,
            _mid: int,
            reason_codes: Sequence[Any],
            _properties: Any,
        ) -> None:
            if reason_codes and any(getattr(code, "is_failure", False) for code in reason_codes):
                self.subscription_failed.set()
                log("MQTT", f"Broker rejected subscription to {self.topic}")
                callback_client.disconnect()
                return
            log("MQTT", f"Subscribed to {self.topic}")

        def on_message(_client: Any, _userdata: Any, message: Any) -> None:
            if message.topic != self.topic:
                log("MQTT", f"Ignored unexpected topic {message.topic}")
                return
            try:
                update = json.loads(message.payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                log("MQTT", f"Ignored invalid report JSON: {exc}")
                return
            if not isinstance(update, Mapping):
                log("MQTT", "Ignored report JSON whose root is not an object")
                return
            self.process_report(update)


        def on_disconnect(
            _client: Any,
            _userdata: Any,
            disconnect_flags: Any,
            reason_code: Any,
            _properties: Any,
        ) -> None:
            if reason_code != 0 and not self.authentication_failed.is_set():
                log("MQTT", f"Disconnected: {reason_code}")

        client.on_connect = on_connect
        client.on_subscribe = on_subscribe
        client.on_message = on_message
        client.on_disconnect = on_disconnect

        try:
            client.connect(str(self.host), MQTT_PORT, keepalive=60)
            client.loop_forever(retry_first_connection=False)
        except KeyboardInterrupt:
            log("MQTT", "Stopped by user")
            try:
                client.disconnect()
            except Exception:
                pass
            return 0
        except ssl.SSLCertVerificationError as exc:
            raise BambuMonitorError(
                f"Pinned TLS certificate verification failed: {exc}"
            ) from exc
        except (ConnectionError, OSError, ssl.SSLError) as exc:
            raise BambuMonitorError(f"MQTT connection failed: {exc}") from exc
        if self.authentication_failed.is_set():
            return 3
        if self.subscription_failed.is_set():
            return 4
        return 0


def choose_automatic_ip(
    candidates: Sequence[Candidate], serial: str
) -> ipaddress.IPv4Address:
    serial_matches = [
        candidate
        for candidate in candidates
        if candidate.serial and candidate.serial.casefold() == serial.casefold()
    ]
    if len(serial_matches) == 1:
        return serial_matches[0].ip
    plausible = [
        candidate
        for candidate in candidates
        if candidate.confidence in {"high", "medium"} and candidate.port_8883_open
    ]
    if len(plausible) == 1:
        return plausible[0].ip
    if not plausible:
        raise BambuMonitorError(
            "Automatic detection found no Bambu candidate with TCP 8883 open."
        )
    raise BambuMonitorError(
        "Automatic detection found multiple candidates; specify --ip."
    )


def parse_local_ip(value: str, context: NetworkContext) -> ipaddress.IPv4Address:
    try:
        ip = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise BambuMonitorError(f"Invalid IPv4 address: {value}") from exc
    if ip not in context.scan_network:
        raise BambuMonitorError(
            f"Refusing address {ip}: it is outside the local scan boundary {context.scan_network}."
        )
    return ip


def command_discover(args: argparse.Namespace) -> int:
    context = get_network_context()
    candidates = discover_candidates(
        context,
        passive_seconds=args.passive_seconds,
        active_seconds=args.active_seconds,
        scan_timeout=args.scan_timeout,
        workers=args.workers,
    )
    if not candidates:
        log("DISCOVERY", "No Bambu SSDP response and no host with TCP 8883 found.")
        return 1
    for candidate in candidates:
        print_candidate(candidate)
    if args.save_cert:
        pin_candidates = [candidate for candidate in candidates if candidate.tls]
        if len(pin_candidates) != 1:
            raise BambuMonitorError(
                "--save-cert requires exactly one TLS-capable candidate; use --ip with monitor or isolate the device."
            )
        saved = save_candidate_certificate(pin_candidates[0], args.save_cert)
        log("TLS", f"Certificate saved for pinning: {saved}")
    return 0


def command_monitor(args: argparse.Namespace) -> int:
    serial = validate_serial(args.serial)
    if not args.access_code.strip():
        raise BambuMonitorError("--access-code must not be empty.")
    device_model = args.model
    context = get_network_context()
    if args.ip:
        host = parse_local_ip(args.ip, context)
    else:
        log("DISCOVERY", "--ip omitted; starting automatic detection.")
        candidates = discover_candidates(
            context,
            passive_seconds=args.passive_seconds,
            active_seconds=args.active_seconds,
            scan_timeout=args.scan_timeout,
            workers=args.workers,
        )
        host = choose_automatic_ip(candidates, serial)
        selected = next((item for item in candidates if item.ip == host), None)
        if not device_model and selected:
            device_model = selected.model
        log("FOUND", f"Selected {host}:{MQTT_PORT}")
    return ReadOnlyMonitor(
        host=host,
        serial=serial,
        access_code=args.access_code,
        cert_file=args.cert_file,
        device_model=device_model,
        sensor_interval=args.sensor_interval,
    ).run()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only Bambu Lab LAN discovery and MQTT status monitor."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def discovery_options(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--passive-seconds", type=float, default=DEFAULT_PASSIVE_SECONDS
        )
        command.add_argument(
            "--active-seconds", type=float, default=DEFAULT_ACTIVE_SECONDS
        )
        command.add_argument(
            "--scan-timeout", type=float, default=DEFAULT_SCAN_TIMEOUT
        )
        command.add_argument("--workers", type=int, default=DEFAULT_WORKERS)

    discover = subparsers.add_parser("discover", help="Discover and diagnose candidates")
    discovery_options(discover)
    discover.add_argument(
        "--save-cert",
        type=Path,
        help="Save the sole candidate's leaf certificate as a PEM trust pin",
    )
    discover.set_defaults(handler=command_discover)

    monitor = subparsers.add_parser("monitor", help="Subscribe to read-only report telemetry")
    discovery_options(monitor)
    monitor.add_argument("--ip", help="Printer IPv4; must be inside the local scan boundary")
    monitor.add_argument("--serial", required=True, help="Printer serial number")
    monitor.add_argument("--access-code", required=True, help="Valid LAN/developer access code")
    monitor.add_argument("--model", help="Optional printer model for model-specific HMS text")
    monitor.add_argument(
        "--sensor-interval", type=float, default=DEFAULT_SENSOR_LOG_INTERVAL,
        help="Seconds between sensor snapshots on incoming reports (default: 5; 0: every report)",
    )
    monitor.add_argument(
        "--cert-file", type=Path,
        help="PEM certificate saved by discover --save-cert (enables TLS pinning)",
    )

    monitor.set_defaults(handler=command_monitor)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    configure_console_encoding()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if not all(math.isfinite(value) for value in (
            args.passive_seconds, args.active_seconds, args.scan_timeout
        )):
            raise BambuMonitorError("Discovery timeouts must be finite numbers.")
        if args.command == "monitor" and (
            not math.isfinite(args.sensor_interval) or args.sensor_interval < 0
        ):
            raise BambuMonitorError("--sensor-interval must be a finite, non-negative number.")
        if args.passive_seconds < 0 or args.active_seconds < 0:
            raise BambuMonitorError("Discovery timeouts must not be negative.")
        if not 0.05 <= args.scan_timeout <= 5.0:
            raise BambuMonitorError("--scan-timeout must be between 0.05 and 5 seconds.")
        if not 1 <= args.workers <= 64:
            raise BambuMonitorError("--workers must be between 1 and 64.")
        return int(args.handler(args))
    except BambuMonitorError as exc:
        log("ERROR", str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
