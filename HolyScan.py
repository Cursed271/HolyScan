# ----- License -------------------------------------------------- # 

#  HolyScan - HolyScan identifies open TCP ports using asynchronous connections, 
#  supplements results with banner probes, and exports structured findings for security assessments.
#  Copyright (c) 2026 - CursedSec (Operated by Cursed271). All rights reserved.

#  This software is an proprietary intellectual property developed for
#  penetration testing, threat modeling, and security research. It   
#  is licensed under the CURSEDSEC OWNERSHIP EDICT:
#
#  🚫 PROHIBITION WARNING 🚫
#  Redistribution, re-uploading, and unauthorized modification are strictly forbidden 
#  under the COE. Use is granted ONLY under the limited terms defined in the official 
#  LICENSE file (COE), which must be included in all copies.

#  DISCLAIMER:
#  This tool is intended for **educational or ethical testing** purposes only.
#  Unauthorized or malicious use of this software against systems without 
#  proper authorization is strictly prohibited and may violate laws and regulations.
#  The author assumes no liability for misuse or damage caused by this tool.

#  🔗 LICENSE: CURSEDSEC OWNERSHIP EDICT (COE)
#  🔗 Repository: https://github.com/Cursed271
#  🔗 Author: Steven Pereira (@Cursed271)

# ----- Libraries ------------------------------------------------ #

import os 
import re
import ssl
import json
import time
import typer
import socket
import asyncio
import urllib.request
from pathlib import Path
from rich.rule import Rule
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.console import Console
import typer.rich_utils as typer_rich
from typing import Any, Dict, List, Optional

# ----- Global Declaration --------------------------------------- #

console = Console()
app = typer.Typer(rich_markup_mode = "rich", add_completion = False, context_settings = {"help_option_names": ["-h", "--help"]})
nmap_services = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
cache_path = Path.home() / ".cache" / "holyscan" / "nmap-services"
audit_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017]

# ----- Utilities ------------------------------------------------ #

def util_loader(count: int = 1000) -> List[int]:
    if not cache_path.is_file():
        try:
            cache_path.parent.mkdir(parents = True, exist_ok = True)
            console.print(f"[#FF6B6B][~] HolyScan Initial Setup: Downloading Services Dataset...")
            urllib.request.urlretrieve(NMAP_SERVICES_URL, cache_path)
        except Exception:
            return list(range(1, count + 1))
    ports_with_freq = []
    try:
        with open(cache_path, "r", encoding = "utf-8", errors = "ignore") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 3 and "/tcp" in parts[1]:
                    port_num = int(parts[1].split("/")[0])
                    frequency = float(parts[2])
                    ports_with_freq.append((port_num, frequency))
    except Exception:
        return list(range(1, count + 1))
    ports_with_freq.sort(key = lambda x: x[1], reverse = True)
    return sorted([p[0] for p in ports_with_freq[:count]])

# ----- Banner Grabbing ------------------------------------------ #

def grab_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp").upper()
    except (OSError, socket.error):
        return "UNKNOWN"

def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout = timeout) as s:
            with ctx.wrap_socket(s, server_hostname = ip) as ss:
                cert = ss.getpeercert(binary_form = False)
                subject = dict(x[0] for x in cert.get("subject", []))
                cn = subject.get("commonName", "Unknown")
                return f"TLS/HTTPS (CN: {cn})"
    except Exception:
        pass
    try:
        with socket.create_connection((ip, port), timeout = timeout) as s:
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
            raw = s.recv(1024).decode("utf-8", errors = "ignore")
            match = re.search(r"Server:\s*([^\r\n]+)", raw, re.IGNORECASE)
            if match:
                return f"HTTP (Server: {match.group(1).strip()})"
            clean_lines = [line.strip() for line in raw.splitlines() if line.strip()]
            if clean_lines:
                return clean_lines[0][:60]
    except Exception:
        pass
    try:
        with socket.create_connection((ip, port), timeout = timeout) as s:
            s.sendall(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors = "ignore").strip()
            if banner:
                return " ".join(banner.splitlines())[:60]
    except Exception:
        pass
    return "No Banner Available"

# ----- Async Engine --------------------------------------------- #

async def async_check(ip: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> Optional[int]:
    async with semaphore:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout = timeout)
            writer.close()
            await writer.wait_closed()
            return port
        except (asyncio.TimeoutError, OSError):
            return None

async def async_scan(ip: str, ports: List[int], concurrency: int = 500, timeout: float = 1.0) -> List[int]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [async_check(ip, p, timeout, sem) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted([p for p in results if p is not None])

# ----- Summary Table -------------------------------------------- #

def summary_table(target: str, findings: List[Dict[str, Any]], elapsed: float) -> None:
    table = Table(
        title = f"[bold white]HolyScan - Port Assessment Summary for {target}",
        border_style = "#C6ECE3",
        header_style = "#C6ECE3",
        expand = False
    )
    table.add_column("Port", style = "bold cyan", justify = "right")
    table.add_column("State", style = "bold green", justify = "center")
    table.add_column("Service", style = "white", justify = "left")
    table.add_column("Version / Identified Banner", style = "yellow", justify = "left")
    for f in findings:
        table.add_row(
            str(f["port"]),
            "OPEN",
            f["service"],
            f["banner"]
        )
    console.print()
    console.print(table)
    console.print(f"[#2ECC71][+] Port Scanning has been completed successfully!")
    console.print(f"[#2ECC71][+] HolyScan identified {len(findings)} open ports.")

# ----- Orchestration -------------------------------------------- #

def orchestrate(target: str, ports: List[int], concurrency: int = 500, timeout_sec: float = 1.0, output_path: Optional[str] = None) -> List[Dict[str, Any]]:
    try:
        resolved_ip = socket.gethostbyname(target.strip())
    except socket.gaierror:
        console.print(f"[bold #FF6B6B][!] HolyScan could not resolve the Target supplied...")
        return []
    console.print(f"[#FF6B6B][~] Target resolved: [bold white]{resolved_ip}[/bold white]")
    start_time = time.perf_counter()
    with console.status(f"[#BB9AF7][~] Scanning {len(ports)} ports at high concurrency ({concurrency} workers)...", spinner = "dots"):
        open_ports = asyncio.run(async_scan(resolved_ip, ports, concurrency = concurrency, timeout = timeout_sec))
    scan_duration = time.perf_counter() - start_time
    console.print(f"[#2ECC71][+] TCP Port Scanning completed successfully in {scan_duration:.2f}s!")
    findings: List[Dict[str, Any]] = []
    if open_ports:
        with console.status(f"[#BB9AF7][~] Fingerprinting services and extracting banners...", spinner = "dots"):
            for p in open_ports:
                service = grab_service(p)
                banner = grab_banner(resolved_ip, p)
                findings.append({
                    "port": p,
                    "state": "open",
                    "service": service,
                    "banner": banner
                })
    summary_table(target, findings, scan_duration)
    if output_path:
        try:
            path = Path(output_path)
            path.parent.mkdir(parents = True, exist_ok = True)
            path.write_text(json.dumps(findings, indent = 2))
            console.print(f"[#2ECC71][+] Report successfully written to [#BB9AF7]{output_path}[/#BB9AF7]")
        except Exception as e:
            console.print(f"[bold #FF6B6B][!] HolyScan encountered an Error while saving the JSON Report")
    return findings

# ----- ASCII Banner --------------------------------------------- #

def ascii() -> None:
    art_content = rf"""
ooooo   ooooo           oooo               .oooooo..o
`888'   `888'           `888              d8P'    `Y8
 888     888   .ooooo.   888  oooo    ooo Y88bo.       .ooooo.   .oooo.   ooo. .oo.
 888ooooo888  d88' `88b  888   `88.  .8'   `"Y8888o.  d88' `"Y8 `P  )88b  `888P"Y88b
 888     888  888   888  888    `88..8'        `"Y88b 888        .oP"888   888   888
 888     888  888   888  888     `888'    oo     .d8P 888   .o8 d8(  888   888   888
o888o   o888o `Y8bod8P' o888o     .8'     8""88888P'  `Y8bod8P' `Y888""8o o888o o888o
                              .o..P'
                              `Y8P'
"""
    art_color = Text(art_content, style = "#C6ECE3")
    art_panel = Panel(art_color, border_style = "#C6ECE3", expand = False)
    console.print(art_panel)
    banner_width = console.measure(art_panel).maximum
    console.print(Rule(style = "#C6ECE3 blink"), width = banner_width)
    console.print(f"  [~] Created by [bold red blink]Cursed271[/bold red blink]")
    console.print(f"  [~] HolyScan - Find the port. Follow the service.")
    console.print(Rule(style = "#C6ECE3 blink"), width = banner_width)
    console.print()
    return banner_width

# ----- Argument Parser ------------------------------------------ #

@app.command()
def argu(
    target: Optional[str] = typer.Option(None, "--target", "-t", help = "Target IP or hostname to scan"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help = "Comma-separated ports or range (e.g. '80,443' or '1-1024')"),
    top_ports: bool = typer.Option(False, "--top-ports", help = "Scan the 1000 most common TCP ports (default)"),
    audit: bool = typer.Option(False, "--audit", help = "Audit high-value offensive ports only"),
    full: bool = typer.Option(False, "--full", "-p-", help = "Scan all 65535 TCP ports"),
    threads: int = typer.Option(500, "--threads", "-n", help = "Asynchronous concurrency limit"),
    timeout: float = typer.Option(1.0, "--timeout", "-w", help = "Connection timeout in seconds"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help = "Save path for JSON export"),
) -> None:
    if not target:
        target = Prompt.ask(f"[#C6ECE3][?] Enter the Target Host or IP Address to scan")
    clean_target = target.strip()
    clean_output = output.strip() if output else None
    target_ports: List[int] = []
    if audit:
        target_ports = audit_ports
    elif full:
        target_ports = list(range(1, 65536))
    elif ports:
        try:
            if "-" in ports:
                s, e = map(int, ports.split("-", 1))
                target_ports = list(range(s, e + 1))
            else:
                target_ports = [int(p.strip()) for p in ports.split(",") if p.strip()]
        except ValueError:
            console.print(f"[bold #FF6B6B][!] Invalid Port Range supplied! Defaulting to 1000 Ports")
            target_ports = util_loader(1000)
    else:
        target_ports = util_loader(1000)
    title_target = clean_target.title()
    console.print(f"[#2ECC71][+] HolyScan initiated a port scan against [bold white]{title_target}[/bold white]")
    orchestrate(
        target = clean_target,
        ports = target_ports,
        concurrency = threads,
        timeout_sec = timeout,
        output_path = clean_output
    )

# ----- Main Function -------------------------------------------- #

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    banner_width = ascii()
    typer_rich.MAX_WIDTH = banner_width
    app()

# ----- End ------------------------------------------------------ #