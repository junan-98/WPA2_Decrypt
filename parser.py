from scapy.all import *
import binascii

class PARSER:
    def __init__(self):
        self.packets = rdpcap('./pcap/WPA2_NO_PMF.pcapng')
        self.Anonce = None
        self.Snonce = None
        self.AP_MAC = None
        self.STA_MAC = None
        self.mics = list()
        self.data = list()


    def get_info(self):
        flag = 0
        for i in range(0, len(self.packets)):
            pkt = self.packets[i]
            # EAPOL패킷일 경우 필요한 정보들을 추출한다.
            if pkt.haslayer(EAPOL):
                if flag == 0:
                    self.AP_MAC = pkt.addr2.replace(':', '')
                    self.STA_MAC = pkt.addr1.replace(':', '')
                    self.Anonce = binascii.b2a_hex(pkt.load[13:45])
                elif flag == 1:
                    self.Snonce = binascii.b2a_hex(pkt.load[13:45])
                    mic1 = binascii.b2a_hex(pkt.load[77:93])
                    self.mics.append(mic1)
                    data = binascii.hexlify(bytes(pkt[EAPOL]))
                    data = data.replace(mic1, b"0"*32)
                    data = binascii.a2b_hex(data)
                    self.data.append(data)
                elif flag == 2:
                    mic2 = binascii.b2a_hex(pkt.load[77:93])
                    self.mics.append(mic2)
                    data = binascii.hexlify(bytes(pkt[EAPOL]))
                    data = data.replace(mic2, b"0"*32)
                    data = binascii.a2b_hex(data)
                    self.data.append(data)
                elif flag == 3:
                    mic3 = binascii.b2a_hex(pkt.load[77:93])
                    self.mics.append(mic3)
                    data = binascii.hexlify(bytes(pkt[EAPOL]))
                    data = data.replace(mic3, b"0"*32)
                    data = binascii.a2b_hex(data)
                    self.data.append(data)
                flag += 1
