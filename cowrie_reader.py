import ipaddress
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

COWRIE_LOG_PATH = Path("/home/soso/cowrie/var/log/cowrie/cowrie.json")



def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()



def _format_time(raw: Any) -> str:
    value = _safe_str(raw)
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return value



def _extract_ip(event: Dict[str, Any]) -> str:
    for key in ("src_ip", "source_ip", "peerIP", "ip", "src"):
        value = _safe_str(event.get(key))
        if value:
            return value
    return ""



def _country_for_ip(ip: str) -> str:
    if not ip:
        return "Unknown"
    try:
        if ipaddress.ip_address(ip).is_private:
            return "LAN"
    except Exception:
        return "Unknown"
    return "Unknown"



def _event_type(event_id: str) -> str:
    if event_id == "cowrie.login.failed":
        return "failed"
    if event_id in {"cowrie.login.success", "cowrie.session.connect"}:
        return "success"
    if event_id == "cowrie.command.input":
        return "command"
    return ""



def _clean_event(event: Dict[str, Any]) -> Dict[str, str]:
    event_id = _safe_str(event.get("eventid"))
    etype = _event_type(event_id)
    if not etype:
        return {}

    ip = _extract_ip(event)
    username = _safe_str(event.get("username"))
    password = _safe_str(event.get("password"))
    command = _safe_str(event.get("input") or event.get("command"))

    item = {
        "failed": etype == "failed",
        "success": etype == "success",
        "command": etype == "command",
        "ip": ip,
        "country": _country_for_ip(ip),
        "username": username,
        "password": password,
        "command_text": command,
        "time": _format_time(event.get("timestamp")),
    }
    return item



def get_clean_events(limit: int = 80, log_path: Path = COWRIE_LOG_PATH) -> List[Dict[str, str]]:
    if limit <= 0:
        return []

    try:
        if not log_path.exists():
            return []
    except Exception:
        return []

    cleaned: List[Dict[str, str]] = []
    try:
        with log_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except Exception:
                    continue
                item = _clean_event(payload)
                if item:
                    cleaned.append(item)
    except Exception:
        return []

    if not cleaned:
        return []

    cleaned.reverse()
    return cleaned[:limit]



def get_cowrie_stats(limit: int = 300, log_path: Path = COWRIE_LOG_PATH) -> Dict[str, Any]:
    events = get_clean_events(limit=limit, log_path=log_path)
    failed = 0
    success = 0
    commands = 0
    ip_counter: Dict[str, int] = {}

    for event in events:
        if event.get("failed"):
            failed += 1
        if event.get("success"):
            success += 1
        if event.get("command"):
            commands += 1

        ip = _safe_str(event.get("ip"))
        if ip:
            ip_counter[ip] = ip_counter.get(ip, 0) + 1

    top_ip = "-"
    top_count = 0
    if ip_counter:
        top_ip, top_count = max(ip_counter.items(), key=lambda item: item[1])

    return {
        "status": "ok",
        "failed_count": failed,
        "success_count": success,
        "command_count": commands,
        "top_ip": top_ip,
        "top_ip_count": top_count,
        "events_sampled": len(events),
    }
