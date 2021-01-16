import os
import io
import base64

from msldap.authentication.ntlm.structures.fields import Fields
from msldap.authentication.ntlm.structures.negotiate_flags import NegotiateFlags
from msldap.authentication.ntlm.structures.version import Version
from msldap.authentication.ntlm.structures.avpair import AVPairs

from msldap.authentication.ntlm.templates.server import NTLMServerTemplates

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
class NTLMChallenge:
	def __init__(self):
		self.Signature         = b'NTLMSSP\x00'
		self.MessageType       = 2
		self.TargetNameFields  = None
		self.NegotiateFlags    = None
		self.ServerChallenge   = None
		self.Reserved          = b'\x00'*8
		self.TargetInfoFields  = None
		self.Version           = None
		self.Payload           = None

		self.TargetName        = None
		self.TargetInfo        = None
		
		
	@staticmethod
	def from_bytes(bbuff):
		return NTLMChallenge.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		t = NTLMChallenge()
		t.Signature         = buff.read(8)
		t.MessageType       = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		t.TargetNameFields  = Fields.from_buffer(buff)
		t.NegotiateFlags    = NegotiateFlags(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		t.ServerChallenge   = buff.read(8)
		t.Reserved          = buff.read(8)
		t.TargetInfoFields  = Fields.from_buffer(buff)
		
		if t.NegotiateFlags & NegotiateFlags.NEGOTIATE_VERSION: 
			t.Version = Version.from_buffer(buff)
			
		currPos = buff.tell()
		t.Payload = buff.read()
			
		if t.TargetNameFields.length != 0:
			buff.seek(t.TargetNameFields.offset, io.SEEK_SET)
			raw_data = buff.read(t.TargetNameFields.length)
			try:
				t.TargetName = raw_data.decode('utf-16le')
			except UnicodeDecodeError:
				# yet another cool bug. 
				t.TargetName = raw_data.decode('utf-8')
				
		if t.TargetInfoFields.length != 0:
			buff.seek(t.TargetInfoFields.offset, io.SEEK_SET)
			raw_data = buff.read(t.TargetInfoFields.length)
			t.TargetInfo = AVPairs.from_bytes(raw_data)
			
		
		
		return t

	@staticmethod
	def construct_from_template(templateName, challenge = os.urandom(8), ess = True):
		version    = NTLMServerTemplates[templateName]['version']
		challenge  = challenge
		targetName = NTLMServerTemplates[templateName]['targetname']
		targetInfo = NTLMServerTemplates[templateName]['targetinfo']
		targetInfo = NTLMServerTemplates[templateName]['targetinfo']
		flags      = NTLMServerTemplates[templateName]['flags']
		if ess:
			flags |= NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY
		else:
			flags &= ~NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY

		return NTLMChallenge.construct(challenge=challenge, targetName = targetName, targetInfo = targetInfo, version = version, flags= flags)
	
	
	# TODO: needs some clearning up (like re-calculating flags when needed)
	@staticmethod
	def construct(challenge = os.urandom(8), targetName = None, targetInfo = None, version = None, flags = None):
		pos = 48
		if version:
			pos += 8
		t = NTLMChallenge()
		t.NegotiateFlags    = flags
		t.Version           = version
		t.ServerChallenge   = challenge
		t.TargetName        = targetName
		t.TargetInfo        = targetInfo

		t.TargetNameFields = Fields(len(t.TargetName.encode('utf-16le')),pos) 
		t.TargetInfoFields = Fields(len(t.TargetInfo.to_bytes()), pos + len(t.TargetName.encode('utf-16le')))

		t.Payload = t.TargetName.encode('utf-16le')
		t.Payload += t.TargetInfo.to_bytes()

		return t

	def to_bytes(self):
		tn = self.TargetName.encode('utf-16le')
		ti = self.TargetInfo.to_bytes()

		buff  = self.Signature
		buff += self.MessageType.to_bytes(4, byteorder = 'little', signed = False)
		buff += self.TargetNameFields.to_bytes()
		buff += self.NegotiateFlags.to_bytes(4, byteorder = 'little', signed = False)
		buff += self.ServerChallenge
		buff += self.Reserved
		buff += self.TargetInfoFields.to_bytes()
		if self.Version:
			buff += self.Version.to_bytes()
		buff += self.Payload

		return buff

	def __repr__(self):
		t  = '== NTLMChallenge ==\r\n'
		t += 'Signature      : %s\r\n' % repr(self.Signature)
		t += 'MessageType    : %s\r\n' % repr(self.MessageType)
		t += 'ServerChallenge: %s\r\n' % repr(self.ServerChallenge)
		t += 'TargetName     : %s\r\n' % repr(self.TargetName)
		t += 'TargetInfo     : %s\r\n' % repr(self.TargetInfo)
		return t

	def toBase64(self):
		return base64.b64encode(self.to_bytes()).decode('ascii')


def test():
	test_reconstrut()
	test_construct()
	test_template()
	
def test_reconstrut(data = None):
	print('=== reconstruct===')
	if not data:
		challenge_test_data = bytes.fromhex('4e544c4d53535000020000000800080038000000158289e2a7314a557bdb11bf000000000000000072007200400000000a0063450000000f540045005300540002000800540045005300540001001200570049004e003200300031003900410044000400120074006500730074002e0063006f007200700003002600570049004e003200300031003900410044002e0074006500730074002e0063006f007200700007000800aec600bfc5fdd40100000000')
	else:
		challenge_test_data = data
	challenge = NTLMChallenge.from_bytes(challenge_test_data)
	print(repr(challenge))
	challenge_test_data_verify = challenge.to_bytes()
	print('====== reconstructed ====')
	print(hexdump(challenge_test_data_verify))
	print('====== original ====')
	print(hexdump(challenge_test_data))
	assert challenge_test_data == challenge_test_data_verify
	
def test_template():
	
	challenge = NTLMChallenge.construct_from_template('Windows2003')
	test_reconstrut(challenge.to_bytes())
	
def test_construct():
	pass
	
