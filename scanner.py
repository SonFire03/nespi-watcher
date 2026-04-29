import logging
import re
import subprocess
from typing import Dict, List

logger = logging.getLogger(__name__)

UNKNOWN_MAC = "Inconnue"
UNKNOWN_HOST = "Inconnu"


def _normalize_mac(raw_mac: str) -> str:
    if not raw_mac:
        return UNKNOWN_MAC
    mac = raw_mac.strip().upper().replace("-", ":")
    if re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", mac):
        return mac
    return UNKNOWN_MAC


def _normalize_host(raw_host: str) -> str:
    host = (raw_host or "").strip()
    return host if host else UNKNOWN_HOST


def _build_cmd(network_range: str, profile: str, deep_ports: int) -> List[str]:
    if profile == "deep":
        return ["nmap", "-n", "-T3", f"--top-ports={max(1, deep_ports)}", network_range, "-oX", "-"]
    return ["nmap", "-sn", network_range, "-oX", "-"]


def scan_network(network_range: str, timeout: int = 60, profile: str = "quick", deep_ports: int = 100) -> List[Dict[str, str]]:
    cmd = _build_cmd(network_range, profile, deep_ports)

    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=max(5, timeout), check=False)
    except FileNotFoundError:
        logger.error("nmap introuvable. Installez nmap côté système.")
        return []
    except subprocess.TimeoutExpired:
        logger.error("Scan nmap dépassé (timeout=%s sec)", timeout)
        return []
    except Exception as exc:
        logger.error("Erreur lancement nmap: %s", exc)
        return []

    if completed.returncode not in (0, 1):
        logger.error("nmap return code inattendu: %s", completed.returncode)

    xml_output = completed.stdout or ""
    if not xml_output.strip():
        logger.warning("Sortie nmap vide")
        return []

    return _parse_nmap_xml(xml_output)


def scan_open_ports(ip: str, top_ports: int = 20, timeout: int = 15) -> List[int]:
    cmd = ["nmap", "-n", "-T3", f"--top-ports={max(1, int(top_ports))}", ip, "-oG", "-"]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=max(3, timeout), check=False)
    except Exception as exc:
        logger.warning("Port scan failed for %s: %s", ip, exc)
        return []

    out = completed.stdout or ""
    ports = set()
    for line in out.splitlines():
        if "Ports:" not in line:
            continue
        _, right = line.split("Ports:", 1)
        for chunk in right.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            p = chunk.split("/", 1)[0].strip()
            state = chunk.split("/")[1].strip() if "/" in chunk else ""
            if p.isdigit() and state == "open":
                ports.add(int(p))
    return sorted(ports)


def _parse_nmap_xml(xml_output: str) -> List[Dict[str, str]]:
    devices: List[Dict[str, str]] = []
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_output)
    except Exception as exc:
        logger.error("Impossible de parser la sortie XML nmap: %s", exc)
        return devices

    for host in root.findall("host"):
        status = host.find("status")
        state = status.get("state") if status is not None else ""
        if state != "up":
            continue

        ip = ""
        mac = UNKNOWN_MAC
        hostname = UNKNOWN_HOST

        for addr in host.findall("address"):
            addrtype = (addr.get("addrtype") or "").lower()
            addrval = (addr.get("addr") or "").strip()
            if addrtype == "ipv4" and addrval:
                ip = addrval
            elif addrtype == "mac":
                mac = _normalize_mac(addrval)

        hostnames = host.find("hostnames")
        if hostnames is not None:
            first_hostname = hostnames.find("hostname")
            if first_hostname is not None:
                hostname = _normalize_host(first_hostname.get("name", ""))

        if not ip:
            continue
        devices.append({"ip": ip, "mac": mac, "hostname": hostname})

    seen = set()
    unique_devices = []
    for dev in devices:
        key = (dev["ip"], dev["mac"])
        if key in seen:
            continue
        seen.add(key)
        unique_devices.append(dev)

    return unique_devices
