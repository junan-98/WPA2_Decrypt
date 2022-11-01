import binascii
from Crypto.Cipher import ARC4, AES
from scapy.all import *

def dot11i_decrypt(parser, TK):
    print(binascii.b2a_hex(TK))
    for pkt in parser.encrypted_pkts:
        print("ENCRYPTED PACKET")
        hexdump(pkt)
        dot11 = pkt[Dot11]
        ccmp = pkt[Dot11CCMP]
        PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(ccmp.PN5,ccmp.PN4,ccmp.PN3,ccmp.PN2,ccmp.PN1,ccmp.PN0)
        TA = dot11.addr2.replace(':','',5)
        if pkt.haslayer(Dot11QoS):
            tid = '{:01x}'.format(pkt[Dot11QoS].TID)
        else:
            tid = '0'
        priority = tid+'0'

        nonce = bytes.fromhex(priority) + bytes.fromhex(TA) + bytes.fromhex(PN)
        enc_cipher = AES.new(TK, AES.MODE_CCM, nonce, mac_len=8)
        # MIC는 제거
        decrypted_data = enc_cipher.decrypt(ccmp.data[:-8])
        print("DECRYPTED PACKET")
        hexdump(decrypted_data)
