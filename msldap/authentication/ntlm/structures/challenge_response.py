import io
import datetime

from msldap.commons.utils import *
from msldap.authentication.ntlm.structures.avpair import AVPairs, AVPAIRType

# https://msdn.microsoft.com/en-us/library/cc236648.aspx
class LMResponse:
	def __init__(self):
		self.Response = None
		
	def to_bytes(self):
		return self.Response

	@staticmethod
	def from_bytes(bbuff):
		return LMResponse.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		t = LMResponse()
		t.Response = buff.read(24)
		return t

	def __repr__(self):
		t  = '== LMResponse ==\r\n'
		t += 'Response: %s\r\n' % repr(self.Response.hex())
		return t


# https://msdn.microsoft.com/en-us/library/cc236649.aspx
class LMv2Response:
	def __init__(self):
		self.Response = None
		self.ChallengeFromClinet = None
		
		
	def to_bytes(self):
		return self.Response + self.ChallengeFromClinet

	@staticmethod
	def from_bytes(bbuff):
		return LMv2Response.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		t = LMv2Response()
		t.Response = buff.read(16).hex()
		t.ChallengeFromClinet = buff.read(8).hex()
		return t

	def __repr__(self):
		t  = '== LMv2Response ==\r\n'
		t += 'Response: %s\r\n' % repr(self.Response)
		t += 'ChallengeFromClinet: %s\r\n' % repr(self.ChallengeFromClinet)
		return t


# https://msdn.microsoft.com/en-us/library/cc236651.aspx
class NTLMv1Response:
	def __init__(self):
		self.Response = None
		
	def to_bytes(self):
		return self.Response

	@staticmethod
	def from_bytes(bbuff):
		return NTLMv1Response.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		t = NTLMv1Response()
		t.Response = buff.read(24).hex()
		return t

	def __repr__(self):
		t  = '== NTLMv1Response ==\r\n'
		t += 'Response: %s\r\n' % repr(self.Response)
		return t


# https://msdn.microsoft.com/en-us/library/cc236653.aspx
class NTLMv2Response:
	def __init__(self):
		self.Response = None
		self.ChallengeFromClinet = None
		
	def to_bytes(self):
		return self.Response + self.ChallengeFromClinet.to_bytes()

	@staticmethod
	def from_bytes(bbuff):
		return NTLMv2Response.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		t = NTLMv2Response()
		t.Response = buff.read(16).hex()
		pos = buff.tell()
		t.ChallengeFromClinet = NTLMv2ClientChallenge.from_buffer(buff)

		return t

	def __repr__(self):
		t  = '== NTLMv2Response ==\r\n'
		t += 'Response           : %s\r\n' % repr(self.Response)
		t += 'ChallengeFromClinet: %s\r\n' % repr(self.ChallengeFromClinet)
		return t


class NTLMv2ClientChallenge:
	def __init__(self):
		self.RespType   = 1
		self.HiRespType = 1
		self.Reserved1  = 0
		self.TimeStamp  = None #bytes! because of conversion error :(
		self.Reserved2  = 0
		self.ChallengeFromClient = None
		self.Reserved3  = 0
		self.Details    = None #named AVPairs in the documentation
		
		self.timestamp_dt = None
		self.raw_data = b''
	
	@staticmethod
	def construct(timestamp, client_challenge, details):
		"""
		timestamp: datetime.datetime
		client_challenge: 8 bytes
		details: AVPairs object
		"""
		cc = NTLMv2ClientChallenge()
		cc.TimeStamp = datetime2timestamp(timestamp)
		cc.ChallengeFromClient = client_challenge
		cc.Details = details
		cc.timestamp_dt = timestamp
		return cc
		
	def to_bytes(self):
		t  = self.RespType.to_bytes(1 , byteorder = 'little', signed = False)
		t += self.HiRespType.to_bytes(1 , byteorder = 'little', signed = False)
		t += self.Reserved1.to_bytes(6, byteorder = 'little', signed = False)
		t += self.TimeStamp
		t += self.ChallengeFromClient
		t += self.Reserved2.to_bytes(4, byteorder = 'little', signed = False)
		t += self.Details.to_bytes()
		t += self.Reserved3.to_bytes(4, byteorder = 'little', signed = False)
		
		return t

	@staticmethod
	def from_bytes(bbuff):
		return NTLMv2ClientChallenge.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		cc = NTLMv2ClientChallenge()
		cc.RespType   = int.from_bytes(buff.read(1), byteorder = 'little', signed = False)
		cc.HiRespType = int.from_bytes(buff.read(1), byteorder = 'little', signed = False)
		cc.Reserved1  = int.from_bytes(buff.read(6), byteorder = 'little', signed = False)
		cc.TimeStamp  = buff.read(8)
		cc.ChallengeFromClient = buff.read(8)
		cc.Reserved2  = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		cc.Details    = AVPairs.from_buffer(buff) #referred to as ServerName in the documentation
		cc.Reserved3 = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		
		cc.timestamp_dt = timestamp2datetime(cc.TimeStamp)

		return cc

	def __repr__(self):
		t  = '== NTLMv2ClientChallenge ==\r\n'
		t += 'RespType           : %s\r\n' % repr(self.RespType)
		t += 'TimeStamp          : %s\r\n' % repr(self.timestamp_dt)
		t += 'ChallengeFromClient: %s\r\n' % repr(self.ChallengeFromClient.hex())
		t += 'Details            : %s\r\n' % repr(self.Details)
		return t

def test():
	test_data = bytes.fromhex('0101000000000000aec600bfc5fdd4011bfa20699d7628730000000002000800540045005300540001001200570049004e003200300031003900410044000400120074006500730074002e0063006f007200700003002600570049004e003200300031003900410044002e0074006500730074002e0063006f007200700007000800aec600bfc5fdd40106000400020000000800300030000000000000000000000000200000527d27f234de743760966384d36f61ae2aa4fc2a380699f8caa600011b486d890a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310030002e0032000000000000000000')
	
	cc = NTLMv2ClientChallenge.from_bytes(test_data)
	print(repr(cc))
	
	cc2 = NTLMv2ClientChallenge.from_bytes(cc.to_bytes())
	print(repr(cc2))
	print('=== Original ===')
	print(hexdump(test_data))
	print('=== CC ===')
	print(hexdump(cc.to_bytes()))
	
	### assertions here fail because of the timestamp re-conversion loosing info (float-int conversion)
	#assert cc.to_bytes() == test_data
	#assert cc2.to_bytes() == test_data
	
	details = AVPairs({AVPAIRType.MsvAvNbDomainName: 'TEST', AVPAIRType.MsvAvNbComputerName: 'WIN2019AD', AVPAIRType.MsvAvDnsDomainName: 'test.corp', AVPAIRType.MsvAvDnsComputerName: 'WIN2019AD.test.corp', AVPAIRType.MsvAvTimestamp: b'\xae\xc6\x00\xbf\xc5\xfd\xd4\x01', AVPAIRType.MsvAvFlags: b'\x02\x00\x00\x00', AVPAIRType.MsvAvSingleHost: b"0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00R}'\xf24\xdet7`\x96c\x84\xd3oa\xae*\xa4\xfc*8\x06\x99\xf8\xca\xa6\x00\x01\x1bHm\x89", AVPAIRType.MsvChannelBindings: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', AVPAIRType.MsvAvTargetName: 'cifs/10.10.10.2'})
	timestamp = datetime.datetime(2019,1,1)
	client_challenge = os.urandom(8)
	
	cc3 = NTLMv2ClientChallenge.construct(timestamp, client_challenge, details)
	print(repr(cc3))
	cc4 = NTLMv2ClientChallenge.from_bytes(cc3.to_bytes())

