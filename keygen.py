# WPA2 Decrypt TEST
from pbkdf2 import PBKDF2
from hashlib import pbkdf2_hmac, sha1
import binascii
import hmac
import parser

class KEY_GENERATOR:
    def __init__(self, parser, ssid, passphrase):
        self.SSID = ssid
        self.passphrase = passphrase
        print(f"[+] SSID: {self.SSID}")
        print(f"[+] passphrase: {self.passphrase}\n")
        print(f"[+] AP_MAC: {parser.AP_MAC}")
        print(f"[+] STA_MAC: {parser.STA_MAC}")
        print(f"[+] Anonce: {parser.Anonce.decode()}")
        print(f"[+] Snonce: {parser.Snonce.decode()}\n")
        self.AP_MAC = binascii.a2b_hex(parser.AP_MAC)
        self.STA_MAC = binascii.a2b_hex(parser.STA_MAC)
        self.Anonce = binascii.a2b_hex(parser.Anonce.decode())
        self.Snonce = binascii.a2b_hex(parser.Snonce.decode())
    # PSK == PMK in WPA2
    def gen_PSK(self):
        PSK = PBKDF2(str.encode(self.passphrase), str.encode(self.SSID), 4096).read(32)
        print(f"[+] PSK: {PSK}")
        return PSK.hex()
    
    def gen_PMK(self):
        # 생성식: PMK = PBKDF2(HMAC−SHA1, PSK, SSID, 4096, 256)
        #PMK = PBKDF2(str.encode(self.passphrase), str.encode(self.SSID), 4096).read(32)# 밑에와 동일한 결과값
        PMK = pbkdf2_hmac('sha1', str.encode(self.passphrase), str.encode(self.SSID), 4096, 32) #256 bit
        print(f"[+] PMK: {PMK.hex()}")
        return PMK

    def gen_PTK(self, PMK):
        # PTK = PRF (PMK + Anonce + SNonce + Mac (AP)+ Mac (SA))
        # quoted-printable data 블록을 바이너리로 역변환하고 바이너리 데이터를 반환합니다
        B = min(self.AP_MAC, self.STA_MAC) + max(self.AP_MAC, self.STA_MAC) + min(self.Anonce, self.Snonce) + max(self.Anonce, self.Snonce)
        A = b'Pairwise key expansion'

        to_byte = 64 # 512 bit
        i = 0
        ret = b''
        # 한번 돌 때 마다 160bit 생성되고, 512bit만 필요하기 때문에 나머지는 자른다.
        while i <= ((to_byte*8 + 159)/160):
            hmacsha1 = hmac.new(PMK, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
            ret = ret + hmacsha1.digest()
            i += 1
                    
        print(f"[+] PTK: {binascii.b2a_hex(ret[:to_byte]).decode()}")
        print(f"    [+] KCK: {binascii.b2a_hex(ret[:16]).decode()}")
        print(f"    [+] KEK: {binascii.b2a_hex(ret[16:32]).decode()}")
        print(f"    [+] TK: {binascii.b2a_hex(ret[32:48]).decode()}")
        print(f"    [+] MIC Tx: {binascii.b2a_hex(ret[48:56]).decode()}")
        print(f"    [+] MIC Rx: {binascii.b2a_hex(ret[56:64]).decode()}\n")
        return ret[:to_byte]
    
    def gen_mics(self, PTK, data):
        # data는 MIC필드를 0으로 set해놓은 핸드쉐이크 메시지
        # KCK를 이용해서 mic계산
        
        mics = [hmac.new(PTK[0:16], i, sha1).digest() for i in data]
        return mics
    
    def verify_mics(self, mics, parser):
        for i in range(0, len(mics)):
            mic1Str = parser.mics[i].upper().decode()
            micStr = binascii.b2a_hex(mics[i]).decode().upper()[:-8]
            print(f"[*] original   mic: {mic1Str}")
            print(f"[*] calculated mic: {micStr}")
            if mic1Str != micStr:
                print("[!] MISMATCHED\n")
                continue
            else: print("[+] MATCHED\n")            


