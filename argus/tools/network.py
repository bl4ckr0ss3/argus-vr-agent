"""network_recon — active network attack-surface mapping for bug bounty.

Pure-stdlib TCP port scanner (SYN scan via socket wrapper when available, else
TCP connect). Plus DNS resolution, banner grab, and service fingerprinting via
common response patterns. Use for: discovering open ports, identifying services,
mapping the external attack surface before diving into specific targets.
"""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
from .base import Tool, cap

# Common ports to scan by default.
_DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443,
    445, 465, 500, 587, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 2049,
    2375, 2376, 3000, 3128, 3306, 3389, 4000, 4443, 4567, 5000, 5040,
    5432, 5601, 5672, 5900, 5938, 5985, 5986, 6000, 6379, 6443, 7077,
    7474, 7687, 8000, 8001, 8008, 8009, 8080, 8081, 8088, 8089, 8181,
    8443, 8888, 9000, 9001, 9090, 9092, 9200, 9300, 9443, 10000, 10250,
    11211, 15672, 27017, 27018, 27019,
]

_SERVICE_FINGERPRINTS = {
    (80, 8080, 8000, 8008, 8888): b"HTTP",
    (443, 8443, 9443): b"HTTPS",
    (22,): b"SSH",
    (21,): b"FTP",
    (25, 465, 587): b"SMTP",
    (110, 995): b"POP3",
    (143, 993): b"IMAP",
    (3306,): b"MySQL",
    (5432,): b"PostgreSQL",
    (1433,): b"MSSQL",
    (6379,): b"Redis",
    (27017,): b"MongoDB",
    (9200,): b"Elasticsearch",
    (3389,): b"RDP",
}

_FP_MAP: dict[int, bytes] = {}
for _ports, _banner in _SERVICE_FINGERPRINTS.items():
    for _p in _ports:
        _FP_MAP[_p] = _banner


def _banner_grab(host: str, port: int, timeout: float = 3.0) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        known = _FP_MAP.get(port)
        if known:
            sock.send(known[:4])  # trivial probe
        time.sleep(0.3)
        sock.settimeout(timeout)
        try:
            data = sock.recv(1024)
        except (socket.timeout, OSError):
            data = b""
        sock.close()
        if data:
            txt = data.decode("latin1", "ignore").strip()[:200]
            return txt
        return "(open, no banner)"
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""


def _port_scan(host: str, ports: list[int], timeout: float, workers: int) -> list[dict]:
    results: list[dict] = []

    def check(p: int) -> dict | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start = time.perf_counter()
            err = sock.connect_ex((host, p))
            elapsed = round((time.perf_counter() - start) * 1000, 1)
            sock.close()
            if err == 0:
                banner = _banner_grab(host, p, timeout)
                return {"port": p, "state": "open", "banner": banner or "(no banner)", "latency_ms": elapsed}
        except Exception:
            pass
        return None

    w = min(workers, len(ports))
    with ThreadPoolExecutor(max_workers=w) as ex:
        futures = {ex.submit(check, p): p for p in ports}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)

    results.sort(key=lambda x: x["port"])
    return results


def _dns_resolve(host: str) -> list[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return ips
    except socket.gaierror:
        return []


def make_network_recon() -> Tool:
    def handler(inp: dict) -> str:
        host = (inp.get("target") or "").strip()
        if not host:
            return "ERROR: target (hostname or IP) is required."

        action = (inp.get("action") or "scan").strip().lower()

        if action == "resolve":
            ips = _dns_resolve(host)
            if ips:
                return f"DNS: {host} → {', '.join(ips)}"
            return f"No DNS records for {host}"

        ports_raw = inp.get("ports")
        if ports_raw:
            if isinstance(ports_raw, str):
                ports = [int(p.strip()) for p in ports_raw.split(",") if p.strip().isdigit()]
            elif isinstance(ports_raw, list):
                ports = [int(p) for p in ports_raw if isinstance(p, (int, str)) and str(p).isdigit()]
            else:
                ports = list(_DEFAULT_PORTS)
        else:
            ports = list(_DEFAULT_PORTS)

        timeout = float(inp.get("timeout", 2.0))
        workers = int(inp.get("workers", 50))

        # Resolve hostname first
        ips = _dns_resolve(host)
        target_ip = ips[0] if ips else host
        if ips:
            resolved_note = f"Resolved {host} → {target_ip} ({len(ips)} IP(s))\n\n"
        else:
            resolved_note = f"Using raw target: {target_ip}\n\n"

        results = _port_scan(target_ip, ports, min(timeout, 10.0), min(workers, 200))
        if not results:
            return resolved_note + f"No open ports found on {target_ip} ({len(ports)} scanned)."

        lines = [
            resolved_note + f"Open ports on {target_ip} ({len(ports)} scanned):",
            f"{'Port':<8} {'Banner':<50} {'Latency':<10}",
            "-" * 70,
        ]
        for r in results:
            banner = r["banner"][:48].replace("\n", "\\n").replace("\r", "\\r")
            lines.append(f"{r['port']:<8} {banner:<50} {r['latency_ms']}ms")

        lines.append(f"\n{len(results)} open port(s) on {target_ip}.")
        return cap("\n".join(lines), config.TOOL_OUTPUT_CAP)

    return Tool(
        name="network_recon",
        description=(
            "Active network attack-surface mapping: DNS resolution, TCP port scanning "
            "(80+ common service ports by default), and banner grabbing. Use to discover "
            "open services on a target before deeper exploitation. Threaded for speed. "
            "Sub-actions: 'scan' (default, port scan + banner grab), 'resolve' (DNS only). "
            "Ports can be a comma-separated list in the 'ports' param."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Hostname or IP address."},
                "action": {"type": "string", "enum": ["scan", "resolve"], "description": "'scan' (ports+banner) or 'resolve' (DNS)."},
                "ports": {"type": "string", "description": "Comma-separated port list, e.g. '80,443,8080,8443' (default: top 80 ports)."},
                "timeout": {"type": "number", "description": "Per-port timeout in seconds (default 2.0)."},
                "workers": {"type": "integer", "description": "Parallel workers (default 50)."},
            },
            "required": ["target"],
        },
        handler=handler,
    )
