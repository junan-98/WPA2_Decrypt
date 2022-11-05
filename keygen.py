# WPA2 Decrypt TEST
from pbkdf2 import PBKDF2
from hashlib import pbkdf2_hmac, sha1, sha256
import subprocess
import os
import binascii
import hmac
import parser

class KEY_GENERATOR:
	def __init__(self, parser, ssid, passphrase):
		print(f"[+] SSID: {ssid}")
		print(f"[+] passphrase: {passphrase}\n")
		print(f"[+] AP_MAC: {parser.AP_MAC}")
		print(f"[+] STA_MAC: {parser.STA_MAC}")
		print(f"[+] Anonce: {parser.Anonce.decode()}")
		print(f"[+] Snonce: {parser.Snonce.decode()}")
		if parser.enc_type == 2:
			print("[*] 802.11i encryption\n")
		else:
			print("[*] 802.11w encryption\n")
		self.enc_type = parser.enc_type
		self.SSID = ssid
		self.passphrase = passphrase
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
		if self.enc_type == 2 or self.enc_type == 3:
			PMK = pbkdf2_hmac('sha1', str.encode(self.passphrase), str.encode(self.SSID), 4096, 32) #256 bit
			print(f"[+] PMK: {PMK.hex()}")
			return PMK

	def gen_PTK(self, PMK):
		# PTK = PRF (PMK + Anonce + SNonce + Mac (AP)+ Mac (SA))
		ret = b''
		to_byte = 64 # 512 bit
		B = min(self.AP_MAC, self.STA_MAC) + max(self.AP_MAC, self.STA_MAC) + min(self.Anonce, self.Snonce) + max(self.Anonce, self.Snonce)
		A = b'Pairwise key expansion'
		i = 0
		if self.enc_type == 2:
			while i <= ((to_byte*8 + 159)/160):
				hmacsha1 = hmac.new(PMK, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
				ret = ret + hmacsha1.digest()
				i += 1

		elif self.enc_type == 3:
			ret = ''
			tmp = subprocess.run(['./dot11w/main2', binascii.hexlify(PMK), binascii.hexlify(B)], stdout = subprocess.PIPE)
			tmp = tmp.stdout
			for i in range(0, len(tmp)):
				ret += chr(tmp[i])
			ret = binascii.unhexlify(ret)

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
				return False
			else: print("[+] MATCHED")
		print("[+] ALL MIC MATCHED\n")
		return True

	def shift_and_add(self, original_data, add_data):
		original_data << 8
		return original_data + add_data

	def xordata(self,data, pad):
		l = len(data)
		tmp_data = int.from_bytes(data, byteorder='big')
		mask = 0xff
		new_data = 0
		for i in range(1, 65):
			# 기존 데이터에서 한비이트씩 꺼내서 XOR
			one_byte = tmp_data&mask
			one_byte ^= pad
			# 새로운 데이터의 값을 한바이트 쉬프트 해주고, XOR된 값을 넣는다.
			new_data = self.shift_and_add(new_data, one_byte)
			mask = mask * 256
		# 어차피 PMK 64byte이니까 그냥 ㄱ
		mask = 0xff
		tmp_data = 0
		#바이트가 역순이기 때문에 아래서부터 한바이트씩 꺼내서 다시 넣어줘야함
		for i in range(1, 65):
			one_byte = new_data&mask
			tmp_data = self.shift_and_add(tmp_data, one_byte)
		ret = tmp_data.to_bytes(length=l, byteorder='big')
		
		return 


