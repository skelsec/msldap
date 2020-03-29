import enum
import io
import os

from minikerberos.protocol.constants import EncryptionType
from minikerberos.protocol import encryption
from minikerberos.crypto.hashing import md5, hmac_md5
from minikerberos.crypto.RC4 import RC4

#TODO: RC4 support!

# https://tools.ietf.org/html/draft-raeburn-krb-rijndael-krb-05
# https://tools.ietf.org/html/rfc2478
# https://tools.ietf.org/html/draft-ietf-krb-wg-gssapi-cfx-02

GSS_WRAP_HEADER = b'\x60\x2b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'

class GSSAPIFlags(enum.IntFlag):
	GSS_C_DCE_STYLE     = 0x1000
	GSS_C_DELEG_FLAG    = 1
	GSS_C_MUTUAL_FLAG   = 2
	GSS_C_REPLAY_FLAG   = 4
	GSS_C_SEQUENCE_FLAG = 8
	GSS_C_CONF_FLAG     = 0x10
	GSS_C_INTEG_FLAG    = 0x20
	
class KG_USAGE(enum.Enum):
	ACCEPTOR_SEAL  = 22
	ACCEPTOR_SIGN  = 23
	INITIATOR_SEAL = 24
	INITIATOR_SIGN = 25
	
class FlagsField(enum.IntFlag):
	SentByAcceptor = 0
	Sealed = 2
	AcceptorSubkey = 4
	
# https://tools.ietf.org/html/rfc4757 (7.2)
class GSSMIC_RC4:
	def __init__(self):
		self.TOK_ID = b'\x01\x01'
		self.SGN_ALG = b'\x11\x00' #HMAC
		self.Filler = b'\xff'*4
		self.SND_SEQ = None
		self.SGN_CKSUM = None

	@staticmethod
	def from_bytes(data):
		return GSSMIC_RC4.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		mic = GSSMIC_RC4()
		mic.TOK_ID = buff.read(2)
		mic.SGN_ALG = buff.read(2)
		mic.Filler =  buff.read(4)
		mic.SND_SEQ = buff.read(8)
		mic.SGN_CKSUM = buff.read(8)
		
		return mic
		
	def to_bytes(self):
		t  = self.TOK_ID
		t += self.SGN_ALG
		t += self.Filler
		t += self.SND_SEQ
		if self.SGN_CKSUM is not None:
			t += self.SGN_CKSUM
	
		return t
		
class GSSWRAP_RC4:
	def __init__(self):
		self.TOK_ID = b'\x02\x01'
		self.SGN_ALG = b'\x11\x00' #HMAC
		self.SEAL_ALG = None
		self.Filler = b'\xFF' * 2
		self.SND_SEQ = None
		self.SGN_CKSUM = None
		self.Confounder = None
	
	@staticmethod
	def from_bytes(data):
		return GSSWRAP_RC4.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		wrap = GSSWRAP_RC4()
		wrap.TOK_ID = buff.read(2)
		wrap.SGN_ALG = buff.read(2)
		wrap.SEAL_ALG = buff.read(2)
		wrap.Filler = buff.read(2)
		wrap.SND_SEQ = buff.read(8)
		wrap.SGN_CKSUM = buff.read(8)
		wrap.Confounder = buff.read(8)
		
		return wrap
	
	def to_bytes(self):
		t  = self.TOK_ID
		t += self.SGN_ALG
		t += self.SEAL_ALG
		t += self.Filler
		t += self.SND_SEQ
		
		if self.SGN_CKSUM:
			t += self.SGN_CKSUM
			if self.Confounder:
				t += self.Confounder
		
	
		return t
		
class GSSAPI_RC4:
	def __init__(self, session_key):
		self.session_key = session_key
	
	def GSS_GetMIC(self, data, sequenceNumber, direction = 'init'):
		GSS_GETMIC_HEADER = b'\x60\x23\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
		
		# Let's pad the data
		pad = (4 - (len(data) % 4)) & 0x3
		padStr = bytes([pad]) * pad
		data += padStr
		
		mic = GSSMIC_RC4()
		
		if direction == 'init':
			mic.SND_SEQ = sequenceNumber.to_bytes(4, 'big', signed = False) + b'\x00'*4
		else:
			mic.SND_SEQ = sequenceNumber.to_bytes(4, 'big', signed = False) + b'\xff'*4
		
		Ksign_ctx = hmac_md5(self.session_key.contents)
		Ksign_ctx.update(b'signaturekey\0')
		Ksign = Ksign_ctx.digest()
		
		id = 15
		temp = md5( id.to_bytes(4, 'little', signed = False) +  mic.to_bytes()[:8] ).digest()
		chksum_ctx = hmac_md5(Ksign)
		chksum_ctx.update(temp)
		mic.SGN_CKSUM = chksum_ctx.digest()[:8]
		
		id = 0
		temp = hmac_md5(self.session_key.contents)
		temp.update(id.to_bytes(4, 'little', signed = False))
		
		Kseq_ctx = hmac_md5(temp.digest())
		Kseq_ctx.update(mic.SGN_CKSUM)
		Kseq = Kseq_ctx.digest()
		
		mic.SGN_CKSUM = RC4(Kseq).encrypt(mic.SND_SEQ)
		
		return GSS_GETMIC_HEADER + mic.to_bytes()
		
	
	def GSS_Wrap(self, data, seq_num, direction = 'init2', encrypt=True, auth_data=None):
		GSS_WRAP_HEADER = b'\x60\x2b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
		
		pad = (8 - (len(data) % 8)) & 0x7
		padStr = bytes([pad]) * pad
		data += padStr
		
		token = GSSWRAP_RC4()
		token.SEAL_ALG = b'\x10\x00'
		
		if direction == 'init':
			token.SND_SEQ = seq_num.to_bytes(4, 'big', signed = False) + b'\x00'*4
		else:
			token.SND_SEQ = seq_num.to_bytes(4, 'big', signed = False) + b'\xff'*4
			
		token.Confounder = os.urandom(8)
		
		temp = hmac_md5(self.session_key.contents)
		temp.update(b'signaturekey\0')
		Ksign = temp.digest()
		
		id = 13
		Sgn_Cksum = md5( id.to_bytes(4, 'little', signed = False) +  token.to_bytes()[:8] + token.Confounder + data).digest()
		temp = hmac_md5(Ksign)
		temp.update(Sgn_Cksum)
		token.SGN_CKSUM = temp.digest()[:8]
		
		
		klocal = b''
		for b in self.session_key.contents:
			klocal += bytes([b ^ 0xf0])
			
		id = 0
		temp = hmac_md5(klocal)
		temp.update(id.to_bytes(4, 'little', signed = False))
		temp = hmac_md5(temp.digest())
		temp.update(seq_num.to_bytes(4, 'big', signed = False))
		Kcrypt = temp.digest()
		
		id = 0
		temp = hmac_md5(self.session_key .contents)
		temp.update(id.to_bytes(4, 'little', signed = False))
		temp = hmac_md5(temp.digest())
		temp.update(token.SGN_CKSUM)
		Kseq = temp.digest()
		
		token.SND_SEQ = RC4(Kseq).encrypt(token.SND_SEQ)
		
		
		if auth_data is not None:
			wrap = GSSWRAP_RC4.from_bytes(auth_data)
			
			id = 0
			temp = hmac_md5(self.session_key.contents)
			temp.update(id.to_bytes(4, 'little', signed = False))
			temp = hmac_md5(temp.digest())
			temp.update(wrap.SGN_CKSUM)
			
			snd_seq = RC4(temp.digest()).encrypt(wrap.SND_SEQ)
			
			id = 0
			temp = hmac_md5(klocal)
			temp.update(id.to_bytes(4, 'little', signed = False))
			temp = hmac_md5(temp.digest())
			temp.update(snd_seq[:4])
			Kcrypt = temp.digest()
			
			rc4 = RC4(Kcrypt)
			cipherText = rc4.decrypt(token.Confounder + data)[8:]
			
		elif encrypt is True:
			rc4 = RC4(Kcrypt)
			token.Confounder = rc4.encrypt(token.Confounder)
			cipherText = rc4.encrypt(data)
		
		else:
			cipherText = data
			
		finalData = GSS_WRAP_HEADER + token.to_bytes()
		return cipherText, finalData


	def test_decrypt(self, data, seq_num, direction = 'init2', encrypt=True, auth_data=None):
		import struct
		klocal = b''
		for b in self.session_key.contents:
			klocal += bytes([b ^ 0xf0])

		wrap = GSSWRAP_RC4.from_bytes(auth_data)
		snd_seq = wrap.SND_SEQ

		Kseq = hmac_md5(self.session_key.contents)
		Kseq.update(struct.pack('<L',0))
		Kseq = Kseq.digest()
		Kseq = hmac_md5(Kseq)
		Kseq.update(wrap.SGN_CKSUM)
		Kseq = Kseq.digest()

		snd_seq = RC4(Kseq).encrypt(wrap.SND_SEQ)
		print('snd_seq %s' % snd_seq)
	
		Kcrypt = hmac_md5(klocal)
		Kcrypt.update(struct.pack('<L',0))
		Kcrypt = Kcrypt.digest()
		Kcrypt = hmac_md5(Kcrypt)
		Kcrypt.update(snd_seq[:4])
		Kcrypt = Kcrypt.digest()
		cipherText = RC4(Kcrypt).decrypt(wrap.Confounder + data)[8:]

		return cipherText, None
		

	def GSS_Unwrap(self, data, seq_num, direction='init', auth_data = None):
		auth_data = data[len(GSS_WRAP_HEADER)+1: len(GSS_WRAP_HEADER)+1 + 32]
		print('auth_data %s' % auth_data)
		data = data[len(GSS_WRAP_HEADER) + 33: ]
		print('data %s' % data)
		return self.test_decrypt(data, seq_num, direction='init', encrypt=False, auth_data=auth_data)
	
# 4.2.6.1. MIC Tokens
class GSSMIC:
	def __init__(self):
		self.TOK_ID = b'\x04\x04'
		self.Flags = None
		self.Filler = b'\xFF' * 5
		self.SND_SEQ = None
		self.SGN_CKSUM = None
		
	@staticmethod
	def from_bytes(data):
		return GSSMIC.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		m = GSSMIC()
		m.TOK_ID = buff.read(2)
		m.Flags = FlagsField(int.from_bytes(buff.read(1), 'big', signed = False))
		m.Filler = buff.read(5)
		m.SND_SEQ = int.from_bytes(buff.read(8), 'big', signed = False)
		m.SGN_CKSUM = buff.read() #should know the size based on the algo!
		return m
		
	def to_bytes(self):
		t  = self.TOK_ID
		t += self.Flags.to_bytes(1, 'big', signed = False)
		t += self.Filler
		t += self.SND_SEQ.to_bytes(8, 'big', signed = False)
		if self.SGN_CKSUM is not None:
			t += self.SGN_CKSUM
		
		return t
		
# 4.2.6.2. Wrap Tokens
class GSSWrapToken:
	def __init__(self):
		self.TOK_ID = b'\x05\x04'
		self.Flags = None
		self.Filler = b'\xFF'
		self.EC = None
		self.RRC = None
		self.SND_SEQ = None
		self.Data = None
		
	@staticmethod
	def from_bytes(data):
		return GSSWrapToken.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		m = GSSWrapToken()
		m.TOK_ID = buff.read(2)
		m.Flags = FlagsField(int.from_bytes(buff.read(1), 'big', signed = False))
		m.Filler = buff.read(1)
		m.EC = int.from_bytes(buff.read(2), 'big', signed = False)
		m.RRC = int.from_bytes(buff.read(2), 'big', signed = False)
		m.SND_SEQ = int.from_bytes(buff.read(8), 'big', signed = False)
		return m
		
	def to_bytes(self):
		t  = self.TOK_ID
		t += self.Flags.to_bytes(1, 'big', signed = False)
		t += self.Filler
		t += self.EC.to_bytes(2, 'big', signed = False)
		t += self.RRC.to_bytes(2, 'big', signed = False)
		t += self.SND_SEQ.to_bytes(8, 'big', signed = False)
		if self.Data is not None:
			t += self.Data
		
		return t
		
class GSSAPI_AES:
	def __init__(self, session_key, cipher_type, checksum_profile):
		self.session_key = session_key
		self.checksum_profile = checksum_profile
		self.cipher_type = cipher_type
		self.cipher = None
		
	def rotate(self, data, numBytes):
		numBytes %= len(data)
		left = len(data) - numBytes
		result = data[left:] + data[:left]
		return result
		
	def unrotate(self, data, numBytes):
		numBytes %= len(data)
		result = data[numBytes:] + data[:numBytes]
		return result
		
	def GSS_GetMIC(self, data, seq_num):
		pad = (4 - (len(data) % 4)) & 0x3
		padStr = bytes([pad]) * pad
		data += padStr
		
		m = GSSMIC()
		m.Flags = FlagsField.AcceptorSubkey
		m.SND_SEQ = seq_num
		checksum_profile = self.checksum_profile()
		m.checksum = checksum_profile.checksum(self.session_key, KG_USAGE.INITIATOR_SIGN.value, data + m.to_bytes()[:16])
		
		return m.to_bytes()
		
	def GSS_Wrap(self, data, seq_num, use_padding = False):
		#raise Exception('not working :/')
		cipher = self.cipher_type()
		pad = 0
		if use_padding is True:
			pad = ((cipher.blocksize - len(data)) % cipher.blocksize) #(cipher.blocksize - (len(data) % cipher.blocksize)) & 15
			padStr = b'\xFF' * pad
			data += padStr
		
		t = GSSWrapToken()
		t.Flags = FlagsField.AcceptorSubkey | FlagsField.Sealed
		t.EC = pad
		t.RRC = 0
		t.SND_SEQ = seq_num
		
		print('Wrap data: %s' % (data + t.to_bytes()))
		cipher_text = cipher.encrypt(self.session_key, KG_USAGE.INITIATOR_SEAL.value,  data + t.to_bytes(), None)
		t.RRC = 28 #[RFC4121] section 4.2.5
		cipher_text = self.rotate(cipher_text, t.RRC + t.EC)
		
		ret1 = cipher_text
		ret2 = t.to_bytes()

		return ret1, ret2
		
	def GSS_Unwrap(self, data, seq_num, direction='init', auth_data = None, use_padding = False):
		print('')
		print('Unwrap data %s' % data[16:])
		print('Unwrap hdr  %s' % data[:16])

		cipher = self.cipher_type()		
		original_hdr = GSSWrapToken.from_bytes(data[:16])
		rotated = data[16:]
		
		cipher_text = self.unrotate(rotated, original_hdr.RRC + original_hdr.EC)
		plain_text = cipher.decrypt(self.session_key, KG_USAGE.ACCEPTOR_SEAL.value, cipher_text)
		new_hdr = GSSWrapToken.from_bytes(plain_text[-16:])

		#signature checking
		new_hdr.RRC = 28
		if data[:16] != new_hdr.to_bytes():
			raise Exception('GSS_Unwrap signature mismatch!')
		

		print('Unwrap checksum: %s' % plain_text[-(original_hdr.EC + 16):])
		print('Unwrap orig chk: %s' % original_hdr.to_bytes())
		print('Unwrap result 1: %s' % plain_text)
		print('Unwrap result  : %s' % plain_text[:-(original_hdr.EC + 16)])
		return plain_text[:-(original_hdr.EC + 16)], None
		
def get_gssapi(session_key):
	if session_key.enctype == encryption.Enctype.AES256:
		return GSSAPI_AES(session_key, encryption._AES256CTS, encryption._SHA1AES256)
	if session_key.enctype == encryption.Enctype.AES128:
		return GSSAPI_AES(session_key, encryption._AES128CTS, encryption._SHA1AES128)
	elif session_key.enctype == encryption.Enctype.RC4:
		return GSSAPI_RC4(session_key)
	else:
		raise Exception('Unsupported etype %s' % session_key.enctype)
		
		
def test():
	#data_padded= bytes.fromhex('810e00001a204de2d64fd111a3da0000f875ae0d1c4500003400000034000000008040050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff')
	#token_1= bytes.fromhex('050406ff000c00000000000000000000')
	#cipherText_1 = bytes.fromhex('0880ed78d6196dde3f3fb23eeea650bc4ae025fa2a9c337c75c024d9d8f0186c75a4a9060e2a40a9ad024317bf5df6a86cb4a764a9ca36843f8fa4f99c03e2bde46f5a29aafc83dacdf9f0a5677446b5d910417142dc7b7ba7ded76cddc4acf9bf7ed44008cb9850e5701f2f9285dad6463ca8d0e365d4f1700f3d054e242ebcde2f3146ddd411a627af7486')
	#cipherText_2 = bytes.fromhex('08cb9850e5701f2f9285dad6463ca8d0e365d4f1700f3d054e242ebcde2f3146ddd411a627af74860880ed78d6196dde3f3fb23eeea650bc4ae025fa2a9c337c75c024d9d8f0186c75a4a9060e2a40a9ad024317bf5df6a86cb4a764a9ca36843f8fa4f99c03e2bde46f5a29aafc83dacdf9f0a5677446b5d910417142dc7b7ba7ded76cddc4acf9bf7ed440')



	#session_key = encryption.Key( encryption.Enctype.AES256 , bytes.fromhex('3e242e91996aadd513ecb1bc2369e44183e08e08c51550fa4b681e77f75ed8e1'))
	#data = bytes.fromhex('810e00001a204de2d64fd111a3da0000f875ae0d1c4500003400000034000000008040050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffff')
	#sequenceNumber = 0
	#ret1 = bytes.fromhex('4ae025fa2a9c337c75c024d9d8f0186c75a4a9060e2a40a9ad024317bf5df6a86cb4a764a9ca36843f8fa4f99c03e2bde46f5a29aafc83dacdf9f0a5677446b5d910417142dc7b7ba7ded76cddc4acf9bf7ed440')
	#ret2 = bytes.fromhex('050406ff000c001c000000000000000008cb9850e5701f2f9285dad6463ca8d0e365d4f1700f3d054e242ebcde2f3146ddd411a627af74860880ed78d6196dde3f3fb23eeea650bc')
	#
	#gssapi = get_gssapi(session_key)
	#r1, r2 = gssapi.GSS_Wrap(data, sequenceNumber)
	#
	#gssapi.GSS_Unwrap(r1, 0, auth_data = b'\xff'*8 + r2)
	#
	#print(r1.hex())
	#print(ret1.hex())
	#
	#assert r1 == ret1
	#assert r2 == ret2

	data = b'\xAF' * 1024
	session_key = encryption.Key( encryption.Enctype.AES256 , bytes.fromhex('3e242e91996aadd513ecb1bc2369e44183e08e08c51550fa4b681e77f75ed8e1'))
	sequenceNumber = 0
	gssapi = get_gssapi(session_key)

	r1, r2 = gssapi.GSS_Wrap(data, sequenceNumber)
	print(len(r2))
	sent = r2 + r1
	print(r1)
	ret1, ret2 = gssapi.GSS_Unwrap(sent, sequenceNumber)

	print(r1.hex())
	print(ret1.hex())





if __name__ == '__main__':
	test()