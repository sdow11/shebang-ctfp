#!/usr/bin/env python3

import re
import subprocess
import os
import sys

command     = 'tcpdump'
param       = '-Aqr' 

#You should run tcpdump process ina terminal and store the data into a .pcap file and feed that file to this script for analysis.
def main():
	print ("Starting packet analyzer.")

    #Execute tcpdump command with params to read packets from .pcap file
	cmdout = subprocess.check_output([command, param, filename])

    decodeddata = cmdout.decode('utf-8')
    print ('\n')

    packets = re.split('\n(?=\d\d:\d\d)', decodeddata)

    for packet in packets:
        print packet

        lines       = packet.splitlines()
        header    = lines[0]
        offset      = len(header)

        timestamp  = packet[:15]
        srcport    = re.search('(?<=\.)(?:(?!\.).)*?(?=\ >)', header).group(0)
        srcip      = re.search('(?<=IP )(?:(?!IP ).)*?(?=\.%s)' % (src_port), header).group(0)
        recvport   = re.search('(?<=\.)(?:(?!\.).)*?(?=\:)', header).group(0)
        recvip     = re.search('(?<=\> )(?:(?!\> ).)*?(?=.%s)' % (recv_port), header).group(0)
        payload     = packet[(offset + 52):]
        data        = '\n||\t\t\t\t'.join(payload.splitlines())

        with open("PACKET_DATA.txt", "a") as packetdata:
            packetdata.write('|| TimeStamp: \t\t%s\n' % (timestamp))
            packetdata.write('|| Source port: \t%s\n' % (srcport))
            packetdata.write('|| Source IP: \t%s' % (srcip))
            packetdata.write('|| Receive port: \t%s\n' % (recvport))
            packetdata.write('|| Receive IP: \t%s' % (recvip))
            packetdata.write('|| Data: \t\t%s\n' % (data))
            packetdata.write('========================== = = = = =  =  =  =  =   =   =   ~    ~    -    -\n')


if __name__ == "__main__":
	args = sys.argv
    if len(args) <= 1:
        print("USAGE:\nRunthe script using format: ./packetanalyzer.py filename.pcap")
        sys.exit()
	else:
		filename = sys.argv[1]





