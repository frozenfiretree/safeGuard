import concurrent.futures
import ipaddress
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
except Exception:
    psutil = None

try:
    from config_app import setup_app_logger

    logger = setup_app_logger("asset_discovery")
except Exception:
    logger = logging.getLogger("asset_discovery")

DEFAULT_PORTS = [22, 53, 80, 135, 139, 161, 443, 445, 3389, 5985, 8080, 8443, 9100]
VIRTUAL_HINTS = ("docker", "veth", "vmware", "virtualbox", "vbox", "hyper-v", "wsl", "loopback", "br-", "virbr")
EXTRA_NETWORKS_ENV = "SAFEGUARD_ASSET_EXTRA_NETWORKS"


def _now() -> float:
    return time.time()


def _log(event: str, **fields: Any) -> None:
    payload = " ".join(f"{key}={value}" for key, value in fields.items() if value is not None)
    logger.info("%s %s", event, payload)


def _log_warning(warnings: List[str], message: str, **fields: Any) -> None:
    warnings.append(message)
    _log("asset_discovery_warning", message=message, **fields)


def _log_error(errors: List[str], message: str, **fields: Any) -> None:
    errors.append(message)
    _log("asset_discovery_error", message=message, **fields)


def get_platform() -> str:
    system = platform.system().lower()
    if system.startswith("windows"):
        return "windows"
    if system.startswith("linux"):
        return "linux"
    return "unknown"


def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run_command(cmd: List[str], timeout: int) -> Tuple[int, str, str]:
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=max(1, int(timeout)),
            check=False,
        )
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", exc.stderr or f"command timed out after {timeout}s"
    except Exception as exc:
        return 1, "", str(exc)


def _normalize_mac(value: Optional[str]) -> str:
    raw = str(value or "").strip().lower().replace("-", ":")
    if not raw or raw in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
        return ""
    parts = [part.zfill(2) for part in raw.split(":") if part]
    if len(parts) < 6:
        return ""
    return ":".join(parts[:6])


def _normalize_ports(ports: Optional[List[int]]) -> List[int]:
    cleaned: List[int] = []
    for port in ports or DEFAULT_PORTS:
        try:
            value = int(port)
        except Exception:
            continue
        if 1 <= value <= 65535:
            cleaned.append(value)
    return sorted(set(cleaned)) or list(DEFAULT_PORTS)


def _is_virtual_interface(name: str) -> bool:
    lowered = str(name or "").lower()
    return any(hint in lowered for hint in VIRTUAL_HINTS)


def _prefix_from_netmask(netmask: str) -> Optional[int]:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except Exception:
        return None


def _valid_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except Exception:
        return False
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
        or str(addr) == "255.255.255.255"
    )


def _gateway_by_interface_windows() -> Dict[str, str]:
    gateways: Dict[str, str] = {}
    code, out, _ = run_command(["route", "print", "-4"], timeout=8)
    if code != 0:
        return gateways
    for line in out.replace("\r", "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gateways.setdefault(parts[3], parts[2])
    return gateways


def _gateway_by_interface_linux() -> Dict[str, str]:
    gateways: Dict[str, str] = {}
    code, out, _ = run_command(["ip", "-4", "route", "show", "default"], timeout=8)
    if code != 0:
        return gateways
    for line in out.replace("\r", "").splitlines():
        parts = line.split()
        if "via" in parts and "dev" in parts:
            gateways[parts[parts.index("dev") + 1]] = parts[parts.index("via") + 1]
    return gateways


def _route_row(cidr: str, gateway: Optional[str], interface_ip: Optional[str], metric: Optional[int], source: str) -> Optional[Dict[str, Any]]:
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except Exception:
        return None
    if network.is_loopback or network.is_link_local or network.is_multicast or network.is_unspecified:
        return None
    return {
        "cidr": str(network),
        "gateway": gateway,
        "interface_ip": interface_ip,
        "metric": metric,
        "source": source,
        "is_default": network.prefixlen == 0,
        "is_host_route": network.prefixlen == 32,
    }


def _collect_windows_routes() -> List[Dict[str, Any]]:
    code, out, _ = run_command(["route", "print", "-4"], timeout=8)
    if code != 0:
        return []
    routes: List[Dict[str, Any]] = []
    in_active = False
    for raw_line in out.replace("\r", "").splitlines():
        line = raw_line.strip()
        if line.startswith("Active Routes:"):
            in_active = True
            continue
        if line.startswith("Persistent Routes:"):
            break
        if not in_active or not line or line.startswith("Network Destination"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        destination, netmask, gateway, interface_ip = parts[:4]
        metric = None
        try:
            metric = int(parts[4])
        except Exception:
            pass
        try:
            cidr = str(ipaddress.IPv4Network(f"{destination}/{netmask}", strict=False))
        except Exception:
            continue
        row = _route_row(cidr, None if gateway.lower() == "on-link" else gateway, interface_ip, metric, "windows_route_print")
        if row:
            row["on_link"] = gateway.lower() == "on-link"
            routes.append(row)
    return routes


def _collect_linux_routes() -> List[Dict[str, Any]]:
    code, out, _ = run_command(["ip", "-4", "route", "show"], timeout=8)
    if code != 0:
        return []
    routes: List[Dict[str, Any]] = []
    for raw_line in out.replace("\r", "").splitlines():
        parts = raw_line.split()
        if not parts:
            continue
        destination = "0.0.0.0/0" if parts[0] == "default" else parts[0]
        gateway = parts[parts.index("via") + 1] if "via" in parts and parts.index("via") + 1 < len(parts) else None
        interface_name = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else None
        metric = None
        if "metric" in parts and parts.index("metric") + 1 < len(parts):
            try:
                metric = int(parts[parts.index("metric") + 1])
            except Exception:
                pass
        row = _route_row(destination, gateway, interface_name, metric, "linux_ip_route")
        if row:
            row["interface"] = interface_name
            row["on_link"] = gateway is None
            routes.append(row)
    return routes


def collect_route_table(current_platform: Optional[str] = None) -> List[Dict[str, Any]]:
    current_platform = current_platform or get_platform()
    if current_platform == "windows":
        return _collect_windows_routes()
    if current_platform == "linux":
        return _collect_linux_routes()
    return []


def _configured_extra_networks() -> List[Dict[str, Any]]:
    raw = os.environ.get(EXTRA_NETWORKS_ENV, "")
    rows: List[Dict[str, Any]] = []
    for item in re.split(r"[;,\\s]+", raw):
        value = item.strip()
        if not value:
            continue
        try:
            network = ipaddress.IPv4Network(value, strict=False)
        except Exception:
            continue
        if network.is_loopback or network.is_link_local or network.is_multicast or network.is_unspecified:
            continue
        rows.append({"cidr": str(network), "source": "configured_extra_network", "raw": value})
    return rows


def get_local_network_context() -> Dict[str, Any]:
    started = time.time()
    current_platform = get_platform()
    warnings: List[str] = []
    interfaces: List[Dict[str, Any]] = []
    gateways_by_key = _gateway_by_interface_windows() if current_platform == "windows" else _gateway_by_interface_linux()
    route_table = collect_route_table(current_platform)
    extra_networks = _configured_extra_networks()

    if psutil is None:
        _log_warning(warnings, "psutil is not installed; local interface discovery is limited", platform=current_platform)
        return {
            "platform": current_platform,
            "local_interfaces": [],
            "route_table": route_table,
            "extra_networks": extra_networks,
            "warnings": warnings,
            "errors": [],
        }

    link_families = {item for item in (getattr(socket, "AF_LINK", None), getattr(psutil, "AF_LINK", None)) if item is not None}
    link_family_names = {"AddressFamily.AF_PACKET", "AddressFamily.AF_LINK", "-1"}
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for if_name, addr_list in addrs.items():
        stat = stats.get(if_name)
        mac = ""
        ipv4_rows = []
        for addr in addr_list:
            family = getattr(addr, "family", None)
            if family in link_families or str(family) in link_family_names:
                mac = _normalize_mac(getattr(addr, "address", ""))
                continue
            if family != socket.AF_INET:
                continue
            ip = getattr(addr, "address", "")
            netmask = getattr(addr, "netmask", "")
            if not _valid_ipv4(ip):
                continue
            prefix = _prefix_from_netmask(netmask)
            if prefix is None:
                continue
            network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
            ipv4_rows.append(
                {
                    "interface": if_name,
                    "ipv4": ip,
                    "ip": ip,
                    "netmask": netmask,
                    "cidr": str(network),
                    "prefixlen": prefix,
                    "gateway": gateways_by_key.get(if_name) or gateways_by_key.get(ip),
                    "mac": mac or None,
                    "is_up": bool(stat.isup) if stat else None,
                    "is_loopback": ipaddress.IPv4Address(ip).is_loopback or _is_virtual_interface(if_name) and "loopback" in if_name.lower(),
                    "is_virtual": _is_virtual_interface(if_name),
                    "interface_type": "virtual" if _is_virtual_interface(if_name) else "physical_or_unknown",
                }
            )
        interfaces.extend(ipv4_rows)

    _log(
        "asset_discovery_context_collected",
        platform=current_platform,
        interfaces=len(interfaces),
        duration_ms=int((time.time() - started) * 1000),
    )
    return {
        "platform": current_platform,
        "local_interfaces": interfaces,
        "route_table": route_table,
        "extra_networks": extra_networks,
        "warnings": warnings,
        "errors": [],
    }


def infer_candidate_networks(context: Dict[str, Any], allow_large_subnet_scan: bool = False) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    def add_candidate(
        cidr: str,
        source_interface: Optional[str],
        local_ip: Optional[str],
        reason: str,
        scan_allowed: bool = True,
        is_virtual: bool = False,
        is_up: Optional[bool] = None,
        gateway: Optional[str] = None,
    ) -> None:
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
        except Exception:
            return
        scan_network = network
        actual_reason = reason
        actual_allowed = scan_allowed
        if network.prefixlen < 24 and not allow_large_subnet_scan:
            if local_ip:
                scan_network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
                actual_reason = f"{reason}_large_subnet_limited_to_local_24"
            else:
                actual_allowed = False
                actual_reason = f"{reason}_large_subnet_skipped"
        estimated_hosts = max(0, scan_network.num_addresses - 2)
        if estimated_hosts > 1024 and not allow_large_subnet_scan:
            actual_allowed = False
            actual_reason = "large_subnet_skipped"
        candidates.append(
            {
                "cidr": str(scan_network),
                "source_interface": source_interface,
                "local_ip": local_ip,
                "gateway": gateway,
                "reason": actual_reason,
                "scan_allowed": actual_allowed,
                "estimated_hosts": estimated_hosts,
                "is_virtual": bool(is_virtual),
                "is_up": is_up,
            }
        )

    for item in context.get("local_interfaces") or []:
        cidr = item.get("cidr")
        local_ip = item.get("ipv4") or item.get("ip")
        if not cidr or not local_ip:
            continue
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            ip_obj = ipaddress.IPv4Address(local_ip)
        except Exception:
            continue
        reason = "direct_connected_ipv4"
        scan_allowed = True
        if item.get("is_up") is False:
            scan_allowed = False
            reason = "interface_down"
        if item.get("is_virtual"):
            scan_allowed = False
            reason = "virtual_interface_skipped_by_default"
        add_candidate(
            str(network),
            item.get("interface"),
            str(ip_obj),
            reason,
            scan_allowed=scan_allowed,
            is_virtual=bool(item.get("is_virtual")),
            is_up=item.get("is_up"),
            gateway=item.get("gateway"),
        )

    for route in context.get("route_table") or []:
        if route.get("is_default") or route.get("is_host_route"):
            continue
        cidr = route.get("cidr")
        if not cidr:
            continue
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
        except Exception:
            continue
        if network.prefixlen < 24 and not allow_large_subnet_scan:
            continue
        add_candidate(
            str(network),
            route.get("interface") or route.get("interface_ip"),
            route.get("interface_ip"),
            "route_table_ipv4",
            scan_allowed=True,
            gateway=route.get("gateway"),
        )

    for extra in context.get("extra_networks") or []:
        cidr = extra.get("cidr")
        if not cidr:
            continue
        add_candidate(cidr, None, None, "configured_extra_network", scan_allowed=True)

    deduped_by_cidr: Dict[str, Dict[str, Any]] = {}
    reason_rank = {
        "direct_connected_ipv4": 0,
        "interface_down": 0,
        "virtual_interface_skipped_by_default": 0,
        "configured_extra_network": 1,
        "route_table_ipv4": 2,
    }
    for row in candidates:
        cidr = row["cidr"]
        previous = deduped_by_cidr.get(cidr)
        if not previous:
            deduped_by_cidr[cidr] = row
            continue
        prev_rank = reason_rank.get(str(previous.get("reason")), 99)
        row_rank = reason_rank.get(str(row.get("reason")), 99)
        if row_rank < prev_rank or (row_rank == prev_rank and row.get("scan_allowed") and not previous.get("scan_allowed")):
            deduped_by_cidr[cidr] = row
    deduped = list(deduped_by_cidr.values())
    deduped.sort(key=lambda row: (not bool(row.get("scan_allowed")), bool(row.get("is_virtual")), row.get("cidr") or ""))
    _log("asset_discovery_candidate_networks", networks=",".join(row["cidr"] for row in deduped), count=len(deduped))
    return deduped


def _asset_template(ip: str, discovery_tool: str) -> Dict[str, Any]:
    return {
        "ip": ip,
        "mac": None,
        "hostname": None,
        "hostname_source": "unknown",
        "os_type": "Unknown",
        "os_source": "unknown",
        "os_confidence": 0,
        "open_ports": [],
        "is_alive": True,
        "discovery_tool": discovery_tool,
        "arp_verified": False,
        "host_discovery_verified": False,
        "icmp_verified": False,
        "tcp_verified": False,
        "suspicious": False,
        "last_seen_at": _now(),
    }


def parse_windows_arp(output: str) -> List[Dict[str, Any]]:
    items: Dict[str, Dict[str, Any]] = {}
    current_interface = None
    for raw_line in (output or "").replace("\r", "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        iface_match = re.match(r"^Interface:\s+([0-9.]+)", line, flags=re.IGNORECASE)
        if iface_match:
            current_interface = iface_match.group(1)
            continue
        match = re.match(r"^([0-9.]+)\s+([0-9a-f:-]{11,})\s+(\w+)", line, flags=re.IGNORECASE)
        if not match:
            continue
        ip = match.group(1)
        mac = _normalize_mac(match.group(2))
        if not _valid_ipv4(ip) or not mac:
            continue
        row = _asset_template(ip, "arp")
        row.update({"mac": mac, "arp_verified": True, "interface_ip": current_interface, "arp_type": match.group(3)})
        items[ip] = row
    return list(items.values())


def parse_linux_ip_neigh(output: str) -> List[Dict[str, Any]]:
    items: Dict[str, Dict[str, Any]] = {}
    for raw_line in (output or "").replace("\r", "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = re.match(r"^([0-9.]+)\s+dev\s+(\S+).*?\s+lladdr\s+([0-9a-f:-]{11,})\s+(\S+)", line, flags=re.IGNORECASE)
        if not match:
            continue
        ip, iface, mac, state = match.group(1), match.group(2), _normalize_mac(match.group(3)), match.group(4)
        if not _valid_ipv4(ip) or not mac:
            continue
        row = _asset_template(ip, "ip_neighbor")
        row.update({"mac": mac, "arp_verified": True, "interface": iface, "neighbor_state": state, "is_alive": state.upper() not in {"FAILED", "INCOMPLETE"}})
        items[ip] = row
    return list(items.values())


def parse_linux_arp(output: str) -> List[Dict[str, Any]]:
    items: Dict[str, Dict[str, Any]] = {}
    for raw_line in (output or "").replace("\r", "").splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("address"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        ip = parts[0]
        mac = next((_normalize_mac(part) for part in parts if re.match(r"^[0-9a-f:-]{11,}$", part, re.I)), "")
        iface = parts[-1] if len(parts) >= 5 else None
        if not _valid_ipv4(ip) or not mac:
            continue
        row = _asset_template(ip, "arp")
        row.update({"mac": mac, "arp_verified": True, "interface": iface})
        items[ip] = row
    return list(items.values())


def collect_neighbor_table(current_platform: str) -> Dict[str, Any]:
    warnings: List[str] = []
    errors: List[str] = []
    assets: List[Dict[str, Any]] = []
    if current_platform == "windows":
        code, out, err = run_command(["arp", "-a"], timeout=8)
        if code == 0:
            assets = parse_windows_arp(out)
        else:
            _log_warning(warnings, f"arp -a failed: {err or code}", platform=current_platform)
    elif current_platform == "linux":
        if command_exists("ip"):
            code, out, err = run_command(["ip", "neigh"], timeout=8)
            if code == 0:
                assets = parse_linux_ip_neigh(out)
            else:
                _log_warning(warnings, f"ip neigh failed: {err or code}", platform=current_platform)
        if not assets and command_exists("arp"):
            code, out, err = run_command(["arp", "-n"], timeout=8)
            if code == 0:
                assets = parse_linux_arp(out)
            else:
                _log_warning(warnings, f"arp -n failed: {err or code}", platform=current_platform)
    else:
        _log_warning(warnings, "unsupported platform for neighbor table", platform=current_platform)
    _log("asset_discovery_arp_done", platform=current_platform, discovered_count=len(assets))
    return {"assets": assets, "warnings": warnings, "errors": errors}


def _parse_nmap_hosts(xml_text: str) -> List[Dict[str, Any]]:
    assets: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return assets
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = None
        mac = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            if addr.get("addrtype") == "mac":
                mac = _normalize_mac(addr.get("addr"))
        if not ip:
            continue
        row = _asset_template(ip, "nmap_ping")
        row.update({"mac": mac or None, "host_discovery_verified": True, "arp_verified": bool(mac)})
        assets.append(row)
    return assets


def nmap_ping_scan(cidr: str, timeout: int) -> Dict[str, Any]:
    warnings: List[str] = []
    if not command_exists("nmap"):
        return {"assets": [], "warnings": ["nmap is not installed; using ping sweep fallback"], "errors": []}
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
        tmp_path = tmp.name
    try:
        code, out, err = run_command(["nmap", "-sn", "-n", "-oX", tmp_path, cidr], timeout=timeout)
        xml_text = Path(tmp_path).read_text(encoding="utf-8", errors="ignore") if Path(tmp_path).exists() else out
        assets = _parse_nmap_hosts(xml_text)
        if code not in (0,):
            _log_warning(warnings, f"nmap ping scan returned {code}: {err}", cidr=cidr)
        return {"assets": assets, "warnings": warnings, "errors": []}
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _ping_one(ip: str, current_platform: str) -> Optional[Dict[str, Any]]:
    cmd = ["ping", "-n", "1", "-w", "500", ip] if current_platform == "windows" else ["ping", "-c", "1", "-W", "1", ip]
    code, out, _ = run_command(cmd, timeout=2)
    if code != 0:
        return None
    row = _asset_template(ip, "ping_sweep")
    row.update({"host_discovery_verified": True, "icmp_verified": True})
    ttl_match = re.search(r"ttl[=\s](\d+)", out, flags=re.IGNORECASE)
    if ttl_match:
        row["ttl"] = int(ttl_match.group(1))
    return row


def ping_sweep(cidr: str, current_platform: str, timeout: int, concurrency: int = 64) -> Dict[str, Any]:
    started = time.time()
    warnings: List[str] = []
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except Exception as exc:
        return {"assets": [], "warnings": [], "errors": [str(exc)]}
    hosts = [str(ip) for ip in network.hosts()]
    assets: List[Dict[str, Any]] = []
    deadline = started + max(1, int(timeout))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(concurrency, 128))) as executor:
        future_map = {executor.submit(_ping_one, ip, current_platform): ip for ip in hosts}
        try:
            iterator = concurrent.futures.as_completed(future_map, timeout=max(1, int(timeout)))
            for future in iterator:
                if time.time() > deadline:
                    _log_warning(warnings, f"ping sweep timed out for {cidr}", cidr=cidr)
                    break
                try:
                    row = future.result(timeout=0)
                    if row:
                        assets.append(row)
                except Exception:
                    continue
        except concurrent.futures.TimeoutError:
            _log_warning(warnings, f"ping sweep timed out for {cidr}", cidr=cidr)
    return {"assets": assets, "warnings": warnings, "errors": []}


def ping_targets(targets: List[str], current_platform: str, timeout: int, concurrency: int = 64) -> Dict[str, Any]:
    ips: List[str] = []
    for target in targets:
        try:
            if "/" in target:
                network = ipaddress.IPv4Network(target, strict=False)
                if network.num_addresses == 1:
                    ips.append(str(network.network_address))
                else:
                    ips.extend(str(ip) for ip in network.hosts())
            else:
                ipaddress.IPv4Address(target)
                ips.append(target)
        except Exception:
            continue
    ips = sorted(set(ips), key=_sort_ip_key)
    if not ips:
        return {"assets": [], "warnings": [], "errors": []}
    if len(ips) > 256:
        return {"assets": [], "warnings": [f"ping target list too large: {len(ips)}"], "errors": []}
    assets: List[Dict[str, Any]] = []
    warnings: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(concurrency, 128))) as executor:
        future_map = {executor.submit(_ping_one, ip, current_platform): ip for ip in ips}
        try:
            for future in concurrent.futures.as_completed(future_map, timeout=max(1, int(timeout))):
                try:
                    row = future.result(timeout=0)
                    if row:
                        assets.append(row)
                except Exception:
                    continue
        except concurrent.futures.TimeoutError:
            _log_warning(warnings, "target ping fallback timed out", targets=len(ips))
    return {"assets": assets, "warnings": warnings, "errors": []}


def nmap_port_scan(ips: List[str], ports: List[int], timeout: int) -> Dict[str, Any]:
    warnings: List[str] = []
    if not ips or not command_exists("nmap"):
        return {"assets": [], "warnings": ["nmap is not installed; using socket port scan fallback"] if ips else [], "errors": []}
    assets: List[Dict[str, Any]] = []
    port_arg = ",".join(str(port) for port in ports)
    for index in range(0, len(ips), 64):
        batch = ips[index : index + 64]
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
            tmp_path = tmp.name
        try:
            code, out, err = run_command(["nmap", "-Pn", "-n", "-T4", "-p", port_arg, "-oX", tmp_path, *batch], timeout=timeout)
            xml_text = Path(tmp_path).read_text(encoding="utf-8", errors="ignore") if Path(tmp_path).exists() else out
            assets.extend(_parse_nmap_ports(xml_text))
            if code != 0:
                _log_warning(warnings, f"nmap port scan returned {code}: {err}", batch=len(batch))
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    return {"assets": assets, "warnings": warnings, "errors": []}


def _parse_nmap_ports(xml_text: str) -> List[Dict[str, Any]]:
    assets: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return assets
    for host in root.findall("host"):
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        if not ip:
            continue
        ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            ports.append(
                {
                    "port": int(port.get("portid") or 0),
                    "protocol": port.get("protocol") or "tcp",
                    "state": "open",
                    "service": service.get("name") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                }
            )
        row = _asset_template(ip, "nmap_port_scan")
        row.update({"open_ports": ports, "tcp_verified": bool(ports), "host_discovery_verified": True})
        assets.append(row)
    return assets


def _socket_probe(ip: str, port: int, connect_timeout: float = 0.5) -> Optional[Dict[str, Any]]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(connect_timeout)
        if sock.connect_ex((ip, int(port))) == 0:
            return {"port": int(port), "protocol": "tcp", "state": "open", "service": None, "version": None}
    return None


def socket_port_scan(ips: List[str], ports: List[int], timeout: int, concurrency: int = 64) -> Dict[str, Any]:
    started = time.time()
    warnings: List[str] = []
    by_ip: Dict[str, Dict[str, Any]] = {ip: _asset_template(ip, "socket_port_scan") for ip in ips}
    tasks = [(ip, port) for ip in ips for port in ports]
    deadline = started + max(1, int(timeout))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(concurrency, 128))) as executor:
        future_map = {executor.submit(_socket_probe, ip, port): (ip, port) for ip, port in tasks}
        try:
            iterator = concurrent.futures.as_completed(future_map, timeout=max(1, int(timeout)))
            for future in iterator:
                if time.time() > deadline:
                    _log_warning(warnings, "socket port scan timed out", ips=len(ips))
                    break
                ip, _ = future_map[future]
                try:
                    port_row = future.result(timeout=0)
                except Exception:
                    port_row = None
                if port_row:
                    by_ip[ip]["open_ports"].append(port_row)
                    by_ip[ip]["tcp_verified"] = True
        except concurrent.futures.TimeoutError:
            _log_warning(warnings, "socket port scan timed out", ips=len(ips))
    return {"assets": list(by_ip.values()), "warnings": warnings, "errors": []}


def resolve_hostname(ip: str, current_platform: str, timeout: int = 2) -> Dict[str, Any]:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname:
            return {"hostname": hostname, "hostname_source": "ptr"}
    except Exception:
        pass
    if current_platform == "windows" and command_exists("nbtstat"):
        code, out, _ = run_command(["nbtstat", "-A", ip], timeout=timeout)
        if code == 0:
            for line in out.replace("\r", "").splitlines():
                match = re.match(r"\s*([A-Za-z0-9_.-]+)\s+<00>\s+UNIQUE", line, flags=re.IGNORECASE)
                if match:
                    return {"hostname": match.group(1), "hostname_source": "netbios"}
    if current_platform == "linux" and command_exists("avahi-resolve-address"):
        code, out, _ = run_command(["avahi-resolve-address", ip], timeout=timeout)
        if code == 0 and out.strip():
            parts = out.split()
            if len(parts) >= 2:
                return {"hostname": parts[1].rstrip("."), "hostname_source": "mdns"}
    return {"hostname": None, "hostname_source": "unknown"}


def resolve_hostnames(assets: List[Dict[str, Any]], current_platform: str, timeout: int = 10, limit: int = 64) -> List[str]:
    warnings: List[str] = []
    pending = [row for row in assets if row.get("ip") and not row.get("hostname")][: max(0, limit)]
    if not pending:
        return warnings
    started = time.time()
    by_ip = {row["ip"]: row for row in pending}
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(16, max(1, len(pending))))
    futures = {executor.submit(resolve_hostname, row["ip"], current_platform, 2): row["ip"] for row in pending}
    try:
        for future in concurrent.futures.as_completed(futures, timeout=max(1, timeout)):
            ip = futures[future]
            try:
                resolved = future.result(timeout=0)
            except Exception:
                resolved = {}
            if resolved.get("hostname"):
                by_ip[ip].update(resolved)
            if time.time() - started > timeout:
                warnings.append("hostname resolution timed out")
                break
    except concurrent.futures.TimeoutError:
        warnings.append("hostname resolution timed out")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return warnings


def infer_os_type(asset: Dict[str, Any]) -> Dict[str, Any]:
    ports = {int(item.get("port")) for item in asset.get("open_ports") or [] if item.get("port")}
    if ports & {135, 139, 445, 3389, 5985}:
        return {"os_type": "Windows", "os_source": "port_fingerprint", "os_confidence": 90}
    if 9100 in ports:
        return {"os_type": "Printer", "os_source": "port_fingerprint", "os_confidence": 80}
    if 161 in ports:
        return {"os_type": "Router", "os_source": "port_fingerprint", "os_confidence": 70}
    if 22 in ports:
        return {"os_type": "Linux", "os_source": "port_fingerprint", "os_confidence": 65}
    ttl = asset.get("ttl")
    try:
        ttl_value = int(ttl)
    except Exception:
        ttl_value = 0
    if ttl_value:
        if ttl_value > 96 and ttl_value <= 128:
            return {"os_type": "Windows", "os_source": "ttl_fingerprint", "os_confidence": 60}
        if ttl_value <= 80:
            return {"os_type": "Linux", "os_source": "ttl_fingerprint", "os_confidence": 55}
        if ttl_value >= 200:
            return {"os_type": "Router", "os_source": "ttl_fingerprint", "os_confidence": 55}
    return {"os_type": "Unknown", "os_source": "unknown", "os_confidence": 0}


def _sort_ip_key(ip: str) -> Tuple[int, int, int, int]:
    try:
        return tuple(int(part) for part in ip.split("."))  # type: ignore[return-value]
    except Exception:
        return (999, 999, 999, 999)


def merge_asset_records(*groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for group in groups:
        for row in group or []:
            ip = str((row or {}).get("ip") or "").strip()
            if not _valid_ipv4(ip):
                continue
            current = dict(merged.get(ip) or _asset_template(ip, "cached"))
            tools = set(str(current.get("discovery_tool") or "").split(","))
            if row.get("discovery_tool"):
                tools.add(str(row.get("discovery_tool")))
            for key, value in row.items():
                if key in {"arp_verified", "host_discovery_verified", "icmp_verified", "tcp_verified", "suspicious"}:
                    continue
                if value not in (None, "", [], {}):
                    if key == "open_ports":
                        existing = {(p.get("protocol"), p.get("port")): p for p in current.get("open_ports") or [] if isinstance(p, dict)}
                        for port_row in value or []:
                            if isinstance(port_row, int):
                                port_row = {"port": port_row, "protocol": "tcp", "state": "open", "service": None, "version": None}
                            if isinstance(port_row, dict):
                                existing[(port_row.get("protocol", "tcp"), port_row.get("port"))] = port_row
                        current["open_ports"] = sorted(existing.values(), key=lambda p: int(p.get("port") or 0))
                    else:
                        current[key] = value
            current["discovery_tool"] = ",".join(sorted(tool for tool in tools if tool and tool != "cached")) or current.get("discovery_tool") or "cached"
            current["arp_verified"] = bool(current.get("arp_verified") or row.get("arp_verified"))
            current["host_discovery_verified"] = bool(current.get("host_discovery_verified") or row.get("host_discovery_verified"))
            current["icmp_verified"] = bool(current.get("icmp_verified") or row.get("icmp_verified"))
            current["tcp_verified"] = bool(current.get("tcp_verified") or row.get("tcp_verified"))
            current.setdefault("hostname", None)
            current.setdefault("hostname_source", "unknown")
            current.setdefault("os_type", "Unknown")
            current.setdefault("os_source", "unknown")
            current.setdefault("os_confidence", 0)
            current.setdefault("suspicious", False)
            current.setdefault("last_seen_at", _now())
            merged[ip] = current
    return [merged[ip] for ip in sorted(merged.keys(), key=_sort_ip_key)]


def _local_host_assets(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    hostname = socket.gethostname()
    mac_fallback = _normalize_mac(":".join(re.findall("..", f"{uuid.getnode():012x}")))
    rows = []
    for iface in context.get("local_interfaces") or []:
        ip = iface.get("ipv4") or iface.get("ip")
        if not ip:
            continue
        row = _asset_template(ip, "local_system")
        row.update(
            {
                "mac": iface.get("mac") or mac_fallback or None,
                "hostname": hostname,
                "hostname_source": "local-system",
                "os_type": platform.system() or "Unknown",
                "os_source": "local-system",
                "os_confidence": 100,
                "arp_verified": bool(iface.get("mac") or mac_fallback),
                "host_discovery_verified": True,
                "icmp_verified": True,
            }
        )
        rows.append(row)
    return rows


def discover_assets(
    targets: Optional[List[str]] = None,
    mode: str = "auto",
    include_port_scan: bool = True,
    include_os_detect: bool = True,
    timeout: int = 60,
    ports: Optional[List[int]] = None,
) -> Dict[str, Any]:
    started = time.time()
    warnings: List[str] = []
    errors: List[str] = []
    current_platform = get_platform()
    _log("asset_discovery_start", platform=current_platform, scan_mode=mode)
    try:
        context = get_local_network_context()
        warnings.extend(context.get("warnings") or [])
        errors.extend(context.get("errors") or [])
        candidates = infer_candidate_networks(context)
        local_assets = _local_host_assets(context)
        neighbor_before = collect_neighbor_table(current_platform)
        warnings.extend(neighbor_before.get("warnings") or [])
        errors.extend(neighbor_before.get("errors") or [])
        neighbor_assets = neighbor_before.get("assets") or []

        scan_targets = list(targets or [])
        if not scan_targets:
            scan_targets = [row["cidr"] for row in candidates if row.get("scan_allowed")]

        host_assets: List[Dict[str, Any]] = []
        host_timeout = max(5, min(int(timeout), 60))
        for target in scan_targets:
            try:
                network = ipaddress.IPv4Network(target, strict=False)
                if network.prefixlen < 24:
                    _log_warning(warnings, f"large target {target} skipped; default scan is limited to /24 or smaller", target=target)
                    continue
            except Exception:
                pass
            if command_exists("nmap"):
                result = nmap_ping_scan(target, timeout=host_timeout)
                ping_result = ping_sweep(target, current_platform, timeout=min(host_timeout, 15), concurrency=64)
                warnings.extend(ping_result.get("warnings") or [])
                errors.extend(ping_result.get("errors") or [])
                host_assets.extend(ping_result.get("assets") or [])
            else:
                result = ping_sweep(target, current_platform, timeout=host_timeout, concurrency=64)
                if not command_exists("nmap"):
                    _log_warning(warnings, "nmap is not installed; ping sweep fallback was used")
            warnings.extend(result.get("warnings") or [])
            errors.extend(result.get("errors") or [])
            host_assets.extend(result.get("assets") or [])

        if targets:
            target_ping_result = ping_targets(scan_targets, current_platform, timeout=min(host_timeout, 15), concurrency=64)
            warnings.extend(target_ping_result.get("warnings") or [])
            errors.extend(target_ping_result.get("errors") or [])
            host_assets.extend(target_ping_result.get("assets") or [])

        neighbor_after = collect_neighbor_table(current_platform)
        warnings.extend(neighbor_after.get("warnings") or [])
        errors.extend(neighbor_after.get("errors") or [])
        neighbor_assets = merge_asset_records(neighbor_assets, neighbor_after.get("assets") or [])
        _log("asset_discovery_host_discovery_done", platform=current_platform, discovered_count=len(host_assets))

        assets = merge_asset_records(local_assets, neighbor_assets, host_assets)
        alive_ips = [row["ip"] for row in assets if row.get("is_alive")]
        scan_ports = _normalize_ports(ports)
        if include_port_scan and alive_ips:
            port_timeout = max(5, min(int(timeout), 60))
            if command_exists("nmap"):
                port_result = nmap_port_scan(alive_ips, scan_ports, timeout=port_timeout)
            else:
                port_result = socket_port_scan(alive_ips, scan_ports, timeout=port_timeout, concurrency=64)
                _log_warning(warnings, "nmap is not installed; socket port scan fallback was used")
            warnings.extend(port_result.get("warnings") or [])
            errors.extend(port_result.get("errors") or [])
            assets = merge_asset_records(assets, port_result.get("assets") or [])
        _log("asset_discovery_port_scan_done", platform=current_platform, discovered_count=len(assets))

        hostname_warnings = resolve_hostnames(assets, current_platform, timeout=min(10, max(2, int(timeout))), limit=64)
        for message in hostname_warnings:
            _log_warning(warnings, message, discovered_count=len(assets))

        if include_os_detect:
            for row in assets:
                if row.get("os_source") in (None, "", "unknown") or row.get("os_type") in (None, "", "Unknown", "unknown"):
                    row.update(infer_os_type(row))

        duration_ms = int((time.time() - started) * 1000)
        _log("asset_discovery_finished", platform=current_platform, discovered_count=len(assets), duration_ms=duration_ms)
        return {
            "status": "ok",
            "platform": current_platform,
            "scan_mode": mode,
            "ports": scan_ports if include_port_scan else [],
            "local_interfaces": context.get("local_interfaces") or [],
            "route_table": context.get("route_table") or [],
            "extra_networks": context.get("extra_networks") or [],
            "candidate_networks": candidates,
            "assets": assets,
            "count": len(assets),
            "errors": errors,
            "warnings": warnings,
            "duration_ms": duration_ms,
        }
    except Exception as exc:
        duration_ms = int((time.time() - started) * 1000)
        _log_error(errors, str(exc), platform=current_platform, duration_ms=duration_ms)
        return {
            "status": "error",
            "platform": current_platform,
            "scan_mode": mode,
            "ports": [],
            "local_interfaces": [],
            "route_table": [],
            "extra_networks": [],
            "candidate_networks": [],
            "assets": [],
            "count": 0,
            "errors": errors,
            "warnings": warnings,
            "duration_ms": duration_ms,
        }
