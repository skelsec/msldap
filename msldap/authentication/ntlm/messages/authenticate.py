import io

from msldap.authentication.ntlm.structures.fields import Fields
from msldap.authentication.ntlm.structures.negotiate_flags import NegotiateFlags
from msldap.authentication.ntlm.structures.version import Version
from msldap.authentication.ntlm.structures.challenge_response import *

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
class NTLMAuthenticate:
	def __init__(self, _use_NTLMv2 = True):
		self.Signature = b'NTLMSSP\x00'
		self.MessageType = 3
		self.LmChallengeResponseFields = None
		self.NtChallengeResponseFields = None
		self.DomainNameFields = None
		self.UserNameFields = None
		self.WorkstationFields = None
		self.EncryptedRandomSessionKeyFields = None
		self.NegotiateFlags = None
		self.Version = None
		self.MIC = None
		self.Payload = None

		# high level
		self.LMChallenge = None
		self.NTChallenge = None
		self.DomainName = None
		self.UserName = None
		self.Workstation = None
		self.EncryptedRandomSession = None

		# this is a global variable that needs to be indicated
		self._use_NTLMv2 = _use_NTLMv2
		
	@staticmethod
	def construct(flags, domainname= None, workstationname= None, username= None, encrypted_session= None, lm_response= None, nt_response= None, version = None, mic = b'\x00'*16):
		auth = NTLMAuthenticate()
		auth.Payload = b''
		
		payload_pos = 8+4+8+8+8+8+8+8+4
		if flags & NegotiateFlags.NEGOTIATE_VERSION:
			if not version:
				raise Exception('NEGOTIATE_VERSION set but no Version supplied!')
				
			auth.Version = version
			
			payload_pos += 8
			
		if mic is not None:
			auth.MIC = mic
			payload_pos += 16
			
		if lm_response:
			data =  lm_response.to_bytes()
			auth.Payload += data
			auth.LmChallengeResponseFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.LMChallenge = lm_response
		else:
			auth.LmChallengeResponseFields  = Fields(0,0)
			
		if nt_response:
			data =  nt_response.to_bytes()
			auth.Payload += data
			auth.NtChallengeResponseFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.NTChallenge = nt_response
		else:
			auth.NtChallengeResponseFields  = Fields(0,0)
		
		
		if domainname:
			data =  domainname.encode('utf-16le')
			auth.Payload += data
			auth.DomainNameFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.DomainName = domainname
		else:
			auth.DomainNameFields  = Fields(0,0)
		
		if username:
			data =  username.encode('utf-16le')
			auth.Payload += data
			auth.UserNameFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.UserName = username
		else:
			auth.UserNameFields  = Fields(0,0)
		
		if workstationname:
			data =  workstationname.encode('utf-16le')
			auth.Payload += data
			auth.WorkstationFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.Workstation = workstationname
		else:
			auth.WorkstationFields  = Fields(0,0)
			
		if encrypted_session:
			data =  encrypted_session
			auth.Payload += data
			auth.EncryptedRandomSessionKeyFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.EncryptedRandomSession = encrypted_session
		else:
			auth.EncryptedRandomSessionKeyFields  = Fields(0,0)
				
		auth.NegotiateFlags = flags		
		return auth
		
	def to_bytes(self):
		t = b''
		t += self.Signature
		t += self.MessageType.to_bytes(4, byteorder = 'little', signed = False)
		
		t += self.LmChallengeResponseFields.to_bytes()
		t += self.NtChallengeResponseFields.to_bytes()
		t += self.DomainNameFields.to_bytes()
		t += self.UserNameFields.to_bytes()
		t += self.WorkstationFields.to_bytes()
		t += self.EncryptedRandomSessionKeyFields.to_bytes()
		t += self.NegotiateFlags.to_bytes(4, byteorder = 'little', signed = False)
		if self.Version:
			t += self.Version.to_bytes()
		if self.MIC is not None:	
			t += self.MIC
		t += self.Payload
		return t
		

	@staticmethod
	def from_bytes(bbuff,_use_NTLMv2 = True):
		return NTLMAuthenticate.from_buffer(io.BytesIO(bbuff), _use_NTLMv2 = _use_NTLMv2)

	@staticmethod
	def from_buffer(buff, _use_NTLMv2 = True):
		auth = NTLMAuthenticate(_use_NTLMv2)
		auth.Signature    = buff.read(8)
		auth.MessageType  = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		auth.LmChallengeResponseFields = Fields.from_buffer(buff)
		auth.NtChallengeResponseFields = Fields.from_buffer(buff)
		auth.DomainNameFields = Fields.from_buffer(buff)
		auth.UserNameFields = Fields.from_buffer(buff)
		auth.WorkstationFields = Fields.from_buffer(buff)
		auth.EncryptedRandomSessionKeyFields = Fields.from_buffer(buff)
		auth.NegotiateFlags = NegotiateFlags(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		if auth.NegotiateFlags & NegotiateFlags.NEGOTIATE_VERSION: 
			auth.Version = Version.from_buffer(buff)

		# TODO: I'm not sure about this condition!!! Need to test this!
		if auth.NegotiateFlags & NegotiateFlags.NEGOTIATE_ALWAYS_SIGN:
			auth.MIC = buff.read(16)

		currPos = buff.tell()
		auth.Payload = buff.read()

		if auth._use_NTLMv2 and auth.NtChallengeResponseFields.length > 24:
			buff.seek(auth.LmChallengeResponseFields.offset, io.SEEK_SET)
			auth.LMChallenge = LMv2Response.from_buffer(buff)
			

			buff.seek(auth.NtChallengeResponseFields.offset, io.SEEK_SET)
			auth.NTChallenge = NTLMv2Response.from_buffer(buff)

		else:
			buff.seek(auth.LmChallengeResponseFields.offset, io.SEEK_SET)
			auth.LMChallenge = LMResponse.from_buffer(buff)
				
			buff.seek(auth.NtChallengeResponseFields.offset, io.SEEK_SET)
			auth.NTChallenge = NTLMv1Response.from_buffer(buff)

		buff.seek(auth.DomainNameFields.offset,io.SEEK_SET)
		auth.DomainName = buff.read(auth.DomainNameFields.length).decode('utf-16le')
		
		buff.seek(auth.UserNameFields.offset,io.SEEK_SET)
		auth.UserName = buff.read(auth.UserNameFields.length).decode('utf-16le')

		buff.seek(auth.WorkstationFields.offset,io.SEEK_SET)
		auth.Workstation = buff.read(auth.WorkstationFields.length).decode('utf-16le')

		buff.seek(auth.EncryptedRandomSessionKeyFields.offset,io.SEEK_SET)
		auth.EncryptedRandomSession = buff.read(auth.EncryptedRandomSessionKeyFields.length)
		
		buff.seek(currPos, io.SEEK_SET)

		return auth

	def __repr__(self):
		t  = '== NTLMAuthenticate ==\r\n'
		t += 'Signature     : %s\r\n' % repr(self.Signature)
		t += 'MessageType   : %s\r\n' % repr(self.MessageType)
		t += 'NegotiateFlags: %s\r\n' % repr(self.NegotiateFlags)
		t += 'Version       : %s\r\n' % repr(self.Version)
		t += 'MIC           : %s\r\n' % repr(self.MIC.hex() if self.MIC else 'None')
		t += 'LMChallenge   : %s\r\n' % repr(self.LMChallenge)
		t += 'NTChallenge   : %s\r\n' % repr(self.NTChallenge)
		t += 'DomainName    : %s\r\n' % repr(self.DomainName)
		t += 'UserName      : %s\r\n' % repr(self.UserName)
		t += 'Workstation   : %s\r\n' % repr(self.Workstation)
		t += 'EncryptedRandomSession: %s\r\n' % repr(self.EncryptedRandomSession.hex())
		return t

def test():
	test_reconstrut()
	test_construct()
	test_2()
	
def test_2():
	data = bytes.fromhex('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 006c 00 00 00 54 00 54 00 84 00 00 00 0c 00 0c 0048 00 00 00 08 00 08 00 54 00 00 00 10 00 10 005c 00 00 00 10 00 10 00 d8 00 00 00 35 82 88 e205 01 28 0a 00 00 00 0f 44 00 6f 00 6d 00 61 0069 00 6e 00 55 00 73 00 65 00 72 00 43 00 4f 004d 00 50 00 55 00 54 00 45 00 52 00 86 c3 50 97ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aaaa aa aa aa 68 cd 0a b8 51 e5 1c 96 aa bc 92 7beb ef 6a 1c 01 01 00 00 00 00 00 00 00 00 00 0000 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 0002 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 0001 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 0000 00 00 00 00 00 00 00 c5 da d2 54 4f c9 79 9094 ce 1c e9 0b c9 d0 3e')
	challenge = NTLMAuthenticate.from_bytes(data)
	print(repr(challenge))
	
def test_reconstrut(data = None):
	print('=== reconstruct===')
	if not data:
		auth_test_data = bytes.fromhex('4e544c4d5353500003000000180018007c000000180118019400000008000800580000000c000c0060000000100010006c00000010001000ac010000158288e20a00d73a0000000f0d98eb57e9c52820709c99b98ca321a15400450053005400760069006300740069006d00570049004e0031003000580036003400000000000000000000000000000000000000000000000000fade3940b9381c53c91ddcdd0d44000b0101000000000000aec600bfc5fdd4011bfa20699d7628730000000002000800540045005300540001001200570049004e003200300031003900410044000400120074006500730074002e0063006f007200700003002600570049004e003200300031003900410044002e0074006500730074002e0063006f007200700007000800aec600bfc5fdd40106000400020000000800300030000000000000000000000000200000527d27f234de743760966384d36f61ae2aa4fc2a380699f8caa600011b486d890a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310030002e003200000000000000000000000000fd67edfb41c09465a91fd733deb0b55b')
	else:
		auth_test_data = data
	challenge = NTLMAuthenticate.from_bytes(auth_test_data)
	print(repr(challenge))
	auth_test_data_verify = challenge.to_bytes()
	print('====== reconstructed ====')
	print(hexdump(auth_test_data_verify))
	print('====== original ====')
	print(hexdump(auth_test_data))
	assert auth_test_data == auth_test_data_verify
	
	
def test_construct():
	pass
	
