# ----- License -------------------------------------------------- # 

#  HolyScan - HolyScan is a lightweight Python tool for port scanning and identifying active services running on remote IP addresses.
#  Copyright (c) 2025 - CursedSec (Operated by Cursed271). All rights reserved.

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
	ip = console.input(rf"[#C6ECE3][?] Enter the IP Address to perform a Port Scan: ")
	console.print(rf"[#C6ECE3][?] Use commas to separate ports or leave blank to scan all Ports")
	port = console.input(rf"[#C6ECE3][?] Enter the Port Number to perform a Port Scan: ")
	ports = list(map(int, port.split(','))) if port else range(1, 65536)
	open_ports = []
	with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
		executor.map(lambda p: scan_ports(ip, p, open_ports), ports)
	if not open_ports:
		console.print(rf"[red][!] Couldn't find any Active Ports for {ip}")
	console.print(rf"[#C6ECE3][+] Port Scanning is Completed!")

# ----- Banner --------------------------------------------------- #

def ascii():
	console.print(rf"""[#C6ECE3]
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
	console.print("[#C6ECE3]+--------------------------------------------------------------+")
	console.print("[#C6ECE3]  HolyScan - Scan Smarter. Find Open Ports Fast.")
	console.print("[#C6ECE3]  Created by [bold black]Cursed271")
	console.print("[#C6ECE3]+--------------------------------------------------------------+")

# ----- Main Function -------------------------------------------- #

if __name__ == "__main__":
	os.system("cls" if os.name == "nt" else "clear")
	ascii()
	multi()
	console.print("[#C6ECE3]+--------------------------------------------------------------+")

# ----- End ------------------------------------------------------ #
