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


def scan_network(network_range: str, timeout: int = 60) -> List[Dict[str, str]]:
    """
    Lance un scan nmap en JSON XML-converti via -oX - puis parsing XML léger.
    On évite python-nmap pour limiter dépendances.
    """
    cmd = [
        "nmap",
        "-sn",
        network_range,
        "-oX",
        "-",
    ]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(5, timeout),
            check=False,
        )
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


def _parse_nmap_xml(xml_output: str) -> List[Dict[str, str]]:
    devices: List[Dict[str, str]] = []

    # Parsing XML robuste avec xml.etree, tolérant aux champs manquants.
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

        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
            }
        )

    # Déduplication par IP+MAC tout en préservant ordre.
    seen = set()
    unique_devices = []
    for dev in devices:
        key = (dev["ip"], dev["mac"])
        if key in seen:
            continue
        seen.add(key)
        unique_devices.append(dev)

    return unique_devices
