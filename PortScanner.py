#!/usr/bin/env python

import socket
import sys

HOSTS = ["localhost"]#, "team2", "team3", "team4"]
PORTLOW = 1
PORTHIGH = 10

def ScanPort(host, port):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		result = sock.connect_ex((host,port))
		if result == 0:
			print("Port {} is open".format(port))
		sock.close()
		return result==0
	except KeyboardInterrupt:
		print("\n Exiting Program !!!!")
		sys.exit()
	except socket.gaierror:
		print("\n Hostname Could Not Be Resolved !!!!")
		sys.exit()
	except socket.error:
		print("\ Server not responding !!!!")
		sys.exit()

def main():
	print ("Starting port scanning.")
	for host in HOSTS:
		print ("Scanning host: " + host)
		for port in range(PORTLOW, PORTHIGH):
			status = "Open" if (ScanPort(host, port) == True) else "Closed"
			print ("Scanning port: " + str(port) + ": " + status)
			

if __name__ == "__main__":
	main()
