# ----- HolyScan --------------------------------------------------------------------------------------------------- #

# HolyScan is a portscanner written in python that lists all the open ports and running services on the host.
# Created by Steven Pereira aka Cursed Cancer
# Github: https://github.com/CursedCancer

# ----- Import Section --------------------------------------------------------------------------------------------- #

import os 
import time
import socket
from rich.console import Console
from threading import Thread
from threading import Lock
from queue import Queue
from datetime import datetime

# ----- Global Declaration ----------------------------------------------------------------------------------------- #

console = Console()
N_Thread = 200
q = Queue()
print_lock = Lock()

# ----- Menu ------------------------------------------------------------------------------------------------------- #

class menu():

	def clear():
		time.sleep(1)
		if os.name == "nt":
			os.system("cls")
		else:
			os.system("clear")

# ----- Banner ----------------------------------------------------------------------------------------------------- #

class banner():

	def ascii():
		console.print(r"""[#79d45e]
        ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
        │     [#a484e9]___  ___  ________  ___           ___    ___      ________  ________  ________  ________[#79d45e]          │
        │    [#a484e9]|\  \|\  \|\   __  \|\  \         |\  \  /  /|    |\   ____\|\   ____\|\   __  \|\   ___  \ [#79d45e]       │
        │    [#a484e9]\ \  \\\  \ \  \|\  \ \  \        \ \  \/  / /    \ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \ [#79d45e]      │
        │     [#a484e9]\ \   __  \ \  \\\  \ \  \        \ \    / /      \ \_____  \ \  \    \ \   __  \ \  \\ \  \ [#79d45e]     │
        │      [#a484e9]\ \  \ \  \ \  \\\  \ \  \____    \/  /  /        \|____|\  \ \  \____\ \  \ \  \ \  \\ \  \ [#79d45e]    │
        │       [#a484e9]\ \__\ \__\ \_______\ \_______\__/  / /            ____\_\  \ \_______\ \__\ \__\ \__\\ \__\ [#79d45e]   │
        │        [#a484e9]\|__|\|__|\|_______|\|_______|\___/ /            |\_________\|_______|\|__|\|__|\|__| \|__|[#79d45e]    │
        │                                     [#a484e9]\|___|/             \|_________|[#79d45e]                                  │    
        │                                                                                                       │
        │                                        [#31bff3]- WELCOME TO HOLY SCAN -[#79d45e]                                       │
        │             Holy Scan is a portscanner written in python that helps to identify open ports            │
        │                                                                                                       │
        │                                                 +-+-+                                                 │
        │                                            [red] Cursed Cancer[#79d45e]                                             │
        │                                                 +-+-+                                                 │
        └───────────────────────────────────────────────────────────────────────────────────────────────────────┘     
        """)

# ----- Port Scanner ----------------------------------------------------------------------------------------------- #

def portscan(port):
	try:
		s = socket.socket()
		s.connect((host, port))
	except:
		with print_lock:
			pass
	else:
		with print_lock:
			serviceName = socket.getservbyport(port)
			service = serviceName.upper()
			console.print(f"\t- {service}: {port}")
	finally:
		s.close()

# ----- Threading -------------------------------------------------------------------------------------------------- #

def scan_thread():
	global q
	while True:
		worker = q.get()
		portscan(worker)
		q.task_done()

def scanner(host, ports):
	global q
	for t in range(N_Thread):
		t = Thread(target=scan_thread)
		t.daemon = True
		t.start()
	for worker in ports:
		q.put(worker)
	q.join()

# ----- Main Function ---------------------------------------------------------------------------------------------- #

if __name__ == '__main__':
	menu.clear()
	banner.ascii()
	console.print("[#5bd2f0]────── [#ffaf68]Performing a Port Scan [#5bd2f0]────────────────────────────────────────────────────────────────────────────────────────\n")
	start = datetime.now()
	remote_server = console.input("[#f6e683]Enter the Host name: ")
	host = socket.gethostbyname(remote_server)
	port = console.input("[#f6e683]Enter the port range: ")
	port_range = port.split("-")
	start = int(port_range[0])
	end = int(port_range[1])
	ports = [p for p in range(start, end)]
	console.print("[#79d45e]Open Ports: ")
	scanner(host, ports)

# ----- End -------------------------------------------------------------------------------------------------------- #
