# ----- License -------------------------------------------------- # 

#  HolyScan - HolyScan scans ports and detects services using a fast, Python-based engine with no external dependencies required.
#  Copyright (c) 2025 - Steven Pereira aka Cursed.

#  This software is an open-source cybersecurity tool developed for
#  penetration testing, threat modeling, and security research. It   
#  is licensed under the MIT License, allowing free use, modification, 
#  and distribution under the following conditions:
#
#  You MUST include this copyright notice in all copies.
#  You MAY use this software for personal or educational purposes ONLY.
#  This software is provided "AS IS," WITHOUT WARRANTY of any kind. 
#  You MAY NOT use this software for any illegal or unauthorized activity.

#  DISCLAIMER:
#  This tool is intended for **educational or ethical testing** purposes only.
#  Unauthorized or malicious use of this software against systems without 
#  proper authorization is strictly prohibited and may violate laws and regulations.
#  The author assumes no liability for misuse or damage caused by this tool.

#  🔗 License: MIT License
#  🔗 Repository: https://github.com/Cursed271
#  🔗 Author: Steven Pereira (@Cursed271)

# ----- Libraries ------------------------------------------------ #

import os
import socket
import argparse
import concurrent.futures
from rich.console import Console

# ----- Global Declaration --------------------------------------- #

console = Console()

# ----- Scanning Function ---------------------------------------- #

def scan_ports(ip, port, open_ports):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.settimeout(1)
		if s.connect_ex((ip, port)) == 0:
			try:
				service = socket.getservbyport(port)
			except:
				service = "Unknown Service"
			console.print(f"[green][+] {service.upper()} is running on Port {port}")
			open_ports.append(port)

# ----- MultiThreading Function ---------------------------------- #

def multi():
	ip = console.input(rf"[#FFA500][?] Enter the IP Address to perform a Port Scan: ")
	console.print(rf"[#FFA500][?] Use commas to separate ports or leave blank to scan all Ports")
	port = console.input(rf"[#FFA500][?] Enter the Port Number to perform a Port Scan: ")
	ports = list(map(int, port.split(','))) if port else range(1, 65536)
	open_ports = []
	with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
		executor.map(lambda p: scan_ports(ip, p, open_ports), ports)
	if not open_ports:
		console.print(rf"[red][!] Couldn't find any Active Ports for {ip}")
	console.print(rf"[green][+] Port Scanning is Completed!")

# ----- Banner --------------------------------------------------- #

def ascii():
	console.print(rf"""[bold green]
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                             │
│    ooooo   ooooo           oooo               .oooooo..o                                    │ 
│    `888'   `888'           `888              d8P'    `Y8                                    │ 
│     888     888   .ooooo.   888  oooo    ooo Y88bo.       .ooooo.   .oooo.   ooo. .oo.      │ 
│     888ooooo888  d88' `88b  888   `88.  .8'   `"Y8888o.  d88' `"Y8 `P  )88b  `888P"Y88b     │ 
│     888     888  888   888  888    `88..8'        `"Y88b 888        .oP"888   888   888     │ 
│     888     888  888   888  888     `888'    oo     .d8P 888   .o8 d8(  888   888   888     │ 
│    o888o   o888o `Y8bod8P' o888o     .8'     8""88888P'  `Y8bod8P' `Y888""8o o888o o888o    │
│                                   .o..P'                                                    │
│                                  `Y8P'                                                      │
│                                                                                             │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
	""")
	console.print("[bold green]+--------------------------------------------------------------+")
	console.print("[bold green]  HolyScan - Fast and Lightweight Command-Line Port Scanner")
	console.print("[bold green]  Created by [bold black]Cursed271")
	console.print("[bold green]+--------------------------------------------------------------+")

# ----- Main Function -------------------------------------------- #

if __name__ == "__main__":
	os.system("cls" if os.name == "nt" else "clear")
	ascii()
	multi()
	console.print("[bold green]+--------------------------------------------------------------+")

# ----- End ------------------------------------------------------ #
