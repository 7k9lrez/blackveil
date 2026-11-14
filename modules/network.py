"""Network Intelligence, Discovery, Port Audit & Traceroute module for BLACKVEIL."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import psutil
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from core.config import ConfigManager
from core.logger import BlackveilLogger
from modules.reports import ReportManager
from modules.system_intel import is_admin

COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NETBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8000: "HTTP-ALT",
    8080: "HTTP-PROXY",
    8443: "HTTPS-ALT",
}


def scapy_available() -> bool:
    """Check whether Scapy can be imported without crashing."""
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


class NetworkModule:
    """Provides real local network inspection, DNS, traceroute, authorized local discovery, and port checks."""

    def __init__(
        self,
        console: Console,
        logger: BlackveilLogger,
        config: ConfigManager,
        reports: ReportManager,
    ) -> None:
        self.console = console
        self.logger = logger
        self.config = config
        self.reports = reports

    def get_primary_local_ip(self) -> str:
        """Determine the primary outbound local IPv4 address without transmitting payload traffic."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.5)
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
        except OSError:
            try:
                return socket.gethostbyname(socket.gethostname())
            except OSError:
                return "127.0.0.1"

    def get_default_gateway(self) -> str:
        """Detect the OS default IPv4 gateway using native routing tools."""
        sys_name = platform.system()
        try:
            if sys_name == "Windows":
                proc = subprocess.run(
                    ["route", "print", "0.0.0.0"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    encoding="utf-8",
                    errors="replace",
                )
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        if self._is_valid_ipv4(parts[2]):
                            return parts[2]
            else:
                proc = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    encoding="utf-8",
                    errors="replace",
                )
                match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", proc.stdout)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return "Unavailable"

    @staticmethod
    def _is_valid_ipv4(addr: str) -> bool:
        try:
            ipaddress.IPv4Address(addr)
            return True
        except ValueError:
            return False

    def collect_interfaces(self) -> list[dict[str, Any]]:
        """Collect all network interfaces, addresses, masks, MACs, and link speeds."""
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        interfaces: list[dict[str, Any]] = []

        for iface_name, addr_list in addrs.items():
            stat = stats.get(iface_name)
            ipv4_entries: list[dict[str, str]] = []
            ipv6_entries: list[str] = []
            mac_addr = "-"

            for item in addr_list:
                family_name = str(item.family)
                if item.family == socket.AF_INET:
                    ipv4_entries.append({"ip": item.address, "netmask": item.netmask or ""})
                elif item.family == socket.AF_INET6:
                    ipv6_entries.append(item.address.split("%")[0])
                elif "AF_LINK" in family_name or "AF_PACKET" in family_name or getattr(psutil, "AF_LINK", None) == item.family:
                    mac_addr = item.address

            interfaces.append(
                {
                    "name": iface_name,
                    "is_up": bool(stat.isup) if stat else False,
                    "speed_mbps": stat.speed if stat else 0,
                    "mtu": stat.mtu if stat else 0,
                    "mac": mac_addr,
                    "ipv4": ipv4_entries,
                    "ipv6": ipv6_entries,
                }
            )
        return interfaces

    def show_network_overview(self, include_connections: bool = False) -> dict[str, Any]:
        """Display local IP, default gateway, interfaces, and optional active connections."""
        local_ip = self.get_primary_local_ip()
        gateway = self.get_default_gateway()
        interfaces = self.collect_interfaces()

        summary = Panel(
            f"[white]Hostname        :[/] [bright_green]{socket.gethostname()}[/]\n"
            f"[white]Primary Local IP:[/] [bright_green]{local_ip}[/]\n"
            f"[white]Default Gateway :[/] [bright_green]{gateway}[/]\n"
            f"[white]Interfaces Found:[/] {len(interfaces)}",
            title="[bold bright_green]NETWORK INTELLIGENCE // OVERVIEW[/]",
            border_style="bright_green",
            box=box.SQUARE,
        )
        self.console.print(summary)

        table = Table(
            title="[bold bright_green]NETWORK INTERFACES[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Interface", style="white")
        table.add_column("State", width=8)
        table.add_column("MAC Address", style="grey70")
        table.add_column("IPv4 / Netmask", style="bright_green")
        table.add_column("Speed", justify="right", style="grey70")

        for iface in interfaces:
            state = "[bright_green]UP[/]" if iface["is_up"] else "[grey50]DOWN[/]"
            ipv4_str = "\n".join(f"{e['ip']} / {e['netmask']}" for e in iface["ipv4"]) or "-"
            speed = f"{iface['speed_mbps']} Mbps" if iface["speed_mbps"] > 0 else "-"
            table.add_row(iface["name"], state, iface["mac"], ipv4_str, speed)

        self.console.print(table)
        result: dict[str, Any] = {
            "hostname": socket.gethostname(),
            "local_ip": local_ip,
            "gateway": gateway,
            "interfaces": interfaces,
        }

        if include_connections:
            conns = self.show_connections()
            result["connections"] = conns

        self.reports.record("NETWORK_INFO", "Local Network Configuration & Interfaces", result)
        return result

    def show_connections(self, limit: int = 40) -> list[dict[str, Any]]:
        """Report live TCP/UDP sockets on the local machine."""
        conns_data: list[dict[str, Any]] = []
        access_denied_count = 0

        try:
            raw_conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.console.print(
                "[bold red][-][/] Permission denied enumerating system-wide sockets. Run as Administrator/root for full socket ownership."
            )
            return []

        for conn in raw_conns:
            pid = conn.pid
            proc_name = "-"
            if pid:
                try:
                    proc_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    access_denied_count += 1
                    proc_name = "protected"

            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
            conns_data.append(
                {
                    "proto": proto,
                    "local": laddr,
                    "remote": raddr,
                    "status": conn.status or "-",
                    "pid": pid or 0,
                    "process": proc_name,
                }
            )

        conns_data.sort(key=lambda c: (c["status"] != "LISTEN", c["status"] != "ESTABLISHED", c["local"]))

        table = Table(
            title=f"[bold bright_green]ACTIVE NETWORK CONNECTIONS (SHOWING {min(limit, len(conns_data))} OF {len(conns_data)})[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Proto", width=6, style="grey70")
        table.add_column("Local Address", style="white")
        table.add_column("Remote Address", style="bright_green")
        table.add_column("State", width=13)
        table.add_column("PID", justify="right", width=7, style="grey70")
        table.add_column("Process", style="white")

        for item in conns_data[:limit]:
            st = item["status"]
            st_colored = f"[bright_green]{st}[/]" if st in {"ESTABLISHED", "LISTEN"} else f"[grey70]{st}[/]"
            table.add_row(
                item["proto"],
                item["local"],
                item["remote"],
                st_colored,
                str(item["pid"]) if item["pid"] else "-",
                item["process"],
            )
        self.console.print(table)
        if access_denied_count > 0 and not is_admin():
            self.console.print("[grey70][*] Note: Some protected process names require Administrator/root privileges.[/]")

        self.reports.record("NETWORK_CONNECTIONS", "Active Host Network Connections", {"count": len(conns_data), "connections": conns_data[:limit]})
        return conns_data

    def resolve_dns(self, domain: str) -> dict[str, Any]:
        """Perform real forward and reverse DNS lookups."""
        domain = domain.strip()
        if not domain:
            self.console.print("[bold red][-][/] Please specify a hostname or IP for DNS resolution.")
            return {}

        start = time.perf_counter()
        ipv4_list: list[str] = []
        ipv6_list: list[str] = []
        reverse_map: dict[str, str] = {}

        try:
            infos = socket.getaddrinfo(domain, None)
            for family, _, _, _, sockaddr in infos:
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in ipv4_list:
                    ipv4_list.append(ip)
                elif family == socket.AF_INET6 and ip not in ipv6_list:
                    ipv6_list.append(ip.split("%")[0])
        except socket.gaierror as exc:
            self.console.print(f"[bold red][-][/] DNS lookup failed for '{domain}': {exc}")
            return {"query": domain, "error": str(exc)}

        for ip in ipv4_list[:5]:
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                reverse_map[ip] = host
            except (socket.herror, socket.gaierror, OSError):
                reverse_map[ip] = "No PTR record"

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        table = Table(
            title=f"[bold bright_green]DNS RESOLUTION // {domain}[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Record Type", style="grey70", width=14)
        table.add_column("Value", style="bright_green")
        table.add_column("PTR / Reverse DNS", style="white")

        for ip in ipv4_list:
            table.add_row("A (IPv4)", ip, reverse_map.get(ip, "-"))
        for ip6 in ipv6_list:
            table.add_row("AAAA (IPv6)", ip6, "-")

        self.console.print(table)
        self.console.print(f"[grey70][+] Query completed in {elapsed_ms} ms[/]")

        payload = {
            "query": domain,
            "ipv4": ipv4_list,
            "ipv6": ipv6_list,
            "reverse_ptr": reverse_map,
            "latency_ms": elapsed_ms,
        }
        self.reports.record("DNS_LOOKUP", f"DNS Resolution: {domain}", payload)
        return payload

    def traceroute(self, target: str, max_hops: int = 20) -> dict[str, Any]:
        """Run a real traceroute to target using OS native tracert/traceroute."""
        target = target.strip()
        try:
            resolved_ip = socket.gethostbyname(target)
        except socket.gaierror as exc:
            self.console.print(f"[bold red][-][/] Cannot resolve target '{target}': {exc}")
            return {"target": target, "error": str(exc)}

        sys_name = platform.system()
        if sys_name == "Windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1500", resolved_ip]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "2", resolved_ip]

        self.console.print(
            f"[bright_green][*][/] Tracing route to [white]{target}[/] ([bright_green]{resolved_ip}[/]), max {max_hops} hops..."
        )
        hops_output: list[str] = []
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                cleaned = line.rstrip()
                if cleaned:
                    hops_output.append(cleaned)
                    self.console.print(f"  [grey70]{cleaned}[/]")
            proc.wait(timeout=45)
        except FileNotFoundError:
            self.console.print(
                "[bold yellow][!][/] System 'traceroute' binary not found. Falling back to TCP reachability probe."
            )
            probe = self.scan_ports(resolved_ip, [80, 443, 22], timeout=1.0)
            return {"target": target, "resolved_ip": resolved_ip, "fallback_probe": probe}
        except KeyboardInterrupt:
            self.console.print("\n[bold yellow][!][/] Traceroute interrupted by user.")
        except Exception as exc:
            self.console.print(f"[bold red][-][/] Traceroute error: {exc}")
            return {"target": target, "error": str(exc)}

        payload = {"target": target, "resolved_ip": resolved_ip, "output": hops_output}
        self.reports.record("TRACEROUTE", f"Traceroute to {target}", payload)
        return payload

    def _detect_local_subnet(self) -> ipaddress.IPv4Network:
        """Infer the active local IPv4 CIDR network from the host's primary interface."""
        primary_ip = self.get_primary_local_ip()
        for iface in self.collect_interfaces():
            for entry in iface["ipv4"]:
                if entry["ip"] == primary_ip and entry["netmask"]:
                    try:
                        net = ipaddress.IPv4Network(f"{entry['ip']}/{entry['netmask']}", strict=False)
                        # Cap overly wide masks to /24 for safe rapid local discovery
                        if net.num_addresses > 1024:
                            return ipaddress.IPv4Network(f"{primary_ip}/24", strict=False)
                        return net
                    except ValueError:
                        pass
        return ipaddress.IPv4Network(f"{primary_ip}/24", strict=False)

    def _probe_host_alive(self, ip_str: str, timeout: float) -> dict[str, Any] | None:
        """Check whether a local subnet host responds to ping or common TCP ports."""
        sys_name = platform.system()
        ping_cmd = (
            ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip_str]
            if sys_name == "Windows"
            else ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip_str]
        )
        alive = False
        method = "ICMP"
        try:
            res = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=timeout + 1.0)
            if res.returncode == 0:
                alive = True
        except Exception:
            pass

        if not alive:
            for port in (80, 443, 445, 22, 135):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(min(timeout, 0.35))
                        if s.connect_ex((ip_str, port)) == 0:
                            alive = True
                            method = f"TCP/{port}"
                            break
                except OSError:
                    continue

        if not alive:
            return None

        hostname = "-"
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
        except OSError:
            pass

        return {"ip": ip_str, "hostname": hostname, "mac": "-", "method": method}

    def _read_arp_cache(self) -> dict[str, str]:
        """Parse OS ARP cache (`arp -a`) to enrich MAC addresses without elevated raw sockets."""
        mac_map: dict[str, str] = {}
        try:
            proc = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
                errors="replace",
            )
            pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")
            for match in pattern.finditer(proc.stdout):
                ip_addr = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                if mac != "FF:FF:FF:FF:FF:FF":
                    mac_map[ip_addr] = mac
        except Exception:
            pass
        return mac_map

    def discover_local_network(self, subnet_cidr: str | None = None) -> list[dict[str, Any]]:
        """Discover live devices on the authorized local subnet using Scapy ARP (if Admin) or ICMP/TCP + ARP cache."""
        try:
            network = ipaddress.IPv4Network(subnet_cidr, strict=False) if subnet_cidr else self._detect_local_subnet()
        except ValueError as exc:
            self.console.print(f"[bold red][-][/] Invalid subnet CIDR '{subnet_cidr}': {exc}")
            return []

        if not network.is_private:
            self.console.print(
                "[bold red][-][/] Safety Policy: 'scan --local' only permits private RFC1918/local subnets (10.x, 172.16-31.x, 192.168.x)."
            )
            return []

        hosts = [str(ip) for ip in network.hosts()]
        if len(hosts) > 1024:
            self.console.print("[bold yellow][!][/] Subnet exceeds 1024 hosts; scanning first 254 addresses in range.")
            hosts = hosts[:254]

        discovered: dict[str, dict[str, Any]] = {}

        if is_admin() and scapy_available():
            try:
                from scapy.all import ARP, Ether, srp  # type: ignore

                self.console.print(f"[bright_green][*][/] Running Scapy Layer-2 ARP discovery on [white]{network}[/]...")
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
                answered, _ = srp(pkt, timeout=2, verbose=0)
                for _, recv in answered:
                    ip_str = recv.psrc
                    try:
                        host_name = socket.gethostbyaddr(ip_str)[0]
                    except OSError:
                        host_name = "-"
                    discovered[ip_str] = {
                        "ip": ip_str,
                        "mac": recv.hwsrc.upper(),
                        "hostname": host_name,
                        "method": "ARP-L2",
                    }
            except Exception as exc:
                self.console.print(f"[yellow][!][/] Scapy L2 ARP unavailable ({exc}); falling back to ICMP/TCP sweep.")

        if not discovered:
            if not is_admin():
                self.console.print(
                    "[grey70][*] Running standard-user ICMP/TCP + ARP cache sweep (Run as Administrator for raw Layer-2 ARP).[/]"
                )
            timeout = float(self.config.get("ping_timeout", 0.8))
            threads = min(int(self.config.get("scan_threads", 64)), max(1, len(hosts)))

            with Progress(
                SpinnerColumn(style="bright_green"),
                TextColumn("[bright_green]{task.description}"),
                BarColumn(bar_width=32, complete_style="bright_green", finished_style="green"),
                TextColumn("[white]{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=self.console,
            ) as progress:
                task = progress.add_task(f"Scanning {network}", total=len(hosts))
                with ThreadPoolExecutor(max_workers=threads) as pool:
                    futures = {pool.submit(self._probe_host_alive, ip, timeout): ip for ip in hosts}
                    for future in as_completed(futures):
                        res = future.result()
                        if res:
                            discovered[res["ip"]] = res
                        progress.advance(task)

            arp_cache = self._read_arp_cache()
            for ip_str, mac in arp_cache.items():
                if ipaddress.IPv4Address(ip_str) in network:
                    if ip_str in discovered:
                        discovered[ip_str]["mac"] = mac
                    else:
                        discovered[ip_str] = {
                            "ip": ip_str,
                            "mac": mac,
                            "hostname": "-",
                            "method": "ARP-CACHE",
                        }

        sorted_hosts = sorted(discovered.values(), key=lambda d: ipaddress.IPv4Address(d["ip"]))
        table = Table(
            title=f"[bold bright_green]LOCAL NETWORK DISCOVERY // {network} ({len(sorted_hosts)} LIVE)[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("IP Address", style="bright_green")
        table.add_column("MAC Address", style="white")
        table.add_column("Hostname", style="grey70")
        table.add_column("Discovery", style="grey70")

        for host in sorted_hosts:
            table.add_row(host["ip"], host["mac"], host["hostname"], host["method"])

        self.console.print(table)
        self.reports.record(
            "LOCAL_DISCOVERY",
            f"Local Subnet Discovery ({network})",
            {"subnet": str(network), "live_hosts": sorted_hosts},
        )
        return sorted_hosts

    @staticmethod
    def parse_port_spec(port_spec: str | None) -> list[int]:
        """Parse port specifications such as '80,443,22' or '1-1024'."""
        if not port_spec or port_spec.lower() == "common":
            return sorted(COMMON_PORTS.keys())

        ports: set[int] = set()
        for chunk in port_spec.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start_s, end_s = chunk.split("-", 1)
                start_p, end_p = int(start_s), int(end_s)
                if start_p < 1 or end_p > 65535 or start_p > end_p:
                    raise ValueError(f"Invalid port range: {chunk}")
                ports.update(range(start_p, end_p + 1))
            else:
                p = int(chunk)
                if p < 1 or p > 65535:
                    raise ValueError(f"Invalid port number: {p}")
                ports.add(p)
        return sorted(ports)

    def _is_authorized_port_target(self, target_ip: str) -> bool:
        """Restrict port checks to loopback or private/local lab subnets."""
        try:
            addr = ipaddress.ip_address(target_ip)
            return addr.is_loopback or addr.is_private or addr.is_link_local
        except ValueError:
            return False

    def _check_single_port(self, ip: str, port: int, timeout: float) -> dict[str, Any] | None:
        """Attempt TCP connect and lightweight service banner grab on an authorized target."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                code = sock.connect_ex((ip, port))
                if code != 0:
                    return None
                banner = ""
                try:
                    sock.settimeout(0.35)
                    if port in {80, 8000, 8080}:
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    raw = sock.recv(128)
                    banner = raw.decode("utf-8", errors="replace").splitlines()[0].strip() if raw else ""
                except Exception:
                    banner = ""
                service = COMMON_PORTS.get(port)
                if not service:
                    try:
                        service = socket.getservbyport(port, "tcp").upper()
                    except OSError:
                        service = "UNKNOWN"
                return {"port": port, "state": "OPEN", "service": service, "banner": banner[:64]}
        except OSError:
            return None

    def scan_ports(
        self,
        target: str = "127.0.0.1",
        ports: list[int] | None = None,
        timeout: float | None = None,
        allow_external: bool = False,
    ) -> list[dict[str, Any]]:
        """Check TCP ports on the local host or authorized private lab target."""
        try:
            resolved_ip = socket.gethostbyname(target)
        except socket.gaierror as exc:
            self.console.print(f"[bold red][-][/] Could not resolve '{target}': {exc}")
            return []

        if not allow_external and not self._is_authorized_port_target(resolved_ip):
            self.console.print(
                f"[bold red][-][/] Target {resolved_ip} is a public address. Port audits are restricted to localhost and private lab subnets (RFC1918) unless --authorized is explicitly confirmed."
            )
            return []

        port_list = ports or sorted(COMMON_PORTS.keys())
        scan_timeout = timeout if timeout is not None else float(self.config.get("scan_timeout", 0.5))
        threads = min(int(self.config.get("scan_threads", 64)), max(1, len(port_list)))
        open_ports: list[dict[str, Any]] = []

        with Progress(
            SpinnerColumn(style="bright_green"),
            TextColumn("[bright_green]{task.description}"),
            BarColumn(bar_width=32, complete_style="bright_green", finished_style="green"),
            TextColumn("[white]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            task = progress.add_task(f"Auditing {len(port_list)} ports on {resolved_ip}", total=len(port_list))
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = [pool.submit(self._check_single_port, resolved_ip, p, scan_timeout) for p in port_list]
                for fut in as_completed(futures):
                    res = fut.result()
                    if res:
                        open_ports.append(res)
                    progress.advance(task)

        open_ports.sort(key=lambda x: x["port"])
        table = Table(
            title=f"[bold bright_green]PORT AUDIT // {target} ({resolved_ip})[/]",
            box=box.SIMPLE_HEAVY,
            border_style="bright_green",
            header_style="bold bright_green",
        )
        table.add_column("Port", style="bright_green", justify="right", width=8)
        table.add_column("State", style="white", width=8)
        table.add_column("Service", style="white", width=16)
        table.add_column("Banner / Fingerprint", style="grey70")

        if not open_ports:
            self.console.print(f"[grey70][*] No open TCP ports detected among {len(port_list)} checked ports on {resolved_ip}.[/]")
        else:
            for item in open_ports:
                table.add_row(str(item["port"]), "[bright_green]OPEN[/]", item["service"], item["banner"] or "-")
            self.console.print(table)

        self.reports.record(
            "PORT_AUDIT",
            f"TCP Port Audit on {target} ({resolved_ip})",
            {"target": target, "resolved_ip": resolved_ip, "checked_count": len(port_list), "open_ports": open_ports},
        )
        return open_ports
