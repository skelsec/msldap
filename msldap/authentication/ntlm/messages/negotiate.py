import io


from msldap.authentication.ntlm.structures.fields import Fields
from msldap.authentication.ntlm.structures.negotiate_flags import NegotiateFlags
from msldap.authentication.ntlm.structures.version import Version

# https://msdn.microsoft.com/en-us/library/cc236641.aspx
class NTLMNegotiate:
	def __init__(self):
		self.Signature         = b'NTLMSSP\x00'
		self.MessageType       = 1
		self.NegotiateFlags    = None
		self.DomainNameFields  = None
		self.WorkstationFields = None
		self.Version           = None
		self.Payload           = None

		####High-level variables
		self.Domain      = None
		self.Workstation = None

	@staticmethod
	def from_bytes(bbuff):
		return NTLMNegotiate.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		t = NTLMNegotiate()
		t.Signature         = buff.read(8)
		t.MessageType       = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		t.NegotiateFlags    = NegotiateFlags(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		t.DomainNameFields  = Fields.from_buffer(buff)
		t.WorkstationFields = Fields.from_buffer(buff)

		if t.NegotiateFlags & NegotiateFlags.NEGOTIATE_VERSION: 
			t.Version = Version.from_buffer(buff)
			
			
		currPos = buff.tell()
		t.Payload = buff.read()

		#currPos = buff.tell()
		
		if t.DomainNameFields.length != 0:
			buff.seek(t.DomainNameFields.offset, io.SEEK_SET)
			raw_data = buff.read(t.WorkstationFields.length)
			#print(raw_data)
			#print(t.DomainNameFields.length)
			try:
				t.Domain = raw_data.decode('utf-16le')
			except UnicodeDecodeError:
				# yet another cool bug. 
				t.Domain = raw_data.decode('utf-8')

		if t.WorkstationFields.length != 0:
			buff.seek(t.WorkstationFields.offset, io.SEEK_SET)
			raw_data = buff.read(t.WorkstationFields.length)
			try:
				t.Workstation = raw_data.decode('utf-16le')
			except UnicodeDecodeError:
				# yet another cool bug. 
				t.Workstation = raw_data.decode('utf-8')

		#buff.seek(currPos, io.SEEK_SET)
		
		return t
		
	@staticmethod
	def construct(flags, domainname = None, workstationname = None, version = None):
		nego = NTLMNegotiate()
		nego.NegotiateFlags = flags
		nego.Payload = b''
		
		payload_pos = 32
		if flags & NegotiateFlags.NEGOTIATE_VERSION:
			if not version:
				raise Exception('NEGOTIATE_VERSION set but no Version supplied!')
			payload_pos += 8
			nego.Version = version
		
		
		
		if nego.NegotiateFlags & NegotiateFlags.NEGOTIATE_OEM_DOMAIN_SUPPLIED and domainname:
			data =  domainname.encode('utf-16le')
			nego.Payload += data
			nego.DomainNameFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			nego.Domain      = data
		
		else:
			nego.DomainNameFields  = Fields(0,0)
		
		if nego.NegotiateFlags & NegotiateFlags.NEGOTIATE_OEM_WORKSTATION_SUPPLIED and workstationname:
			data =  workstationname.encode('utf-16le') 
			nego.Payload += data
			nego.WorkstationFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			nego.Workstation = data
			
		else:
			nego.WorkstationFields  = Fields(0,0)
		
		return nego
		
	def to_bytes(self):
		t = b''
		t += self.Signature
		t += self.MessageType.to_bytes(4, byteorder = 'little', signed = False)
		t += self.NegotiateFlags.to_bytes(4, byteorder = 'little', signed = False)
		t += self.DomainNameFields.to_bytes()		
		t += self.WorkstationFields.to_bytes()
		if self.Version:
			t += self.Version.to_bytes()
		t += self.Payload
		return t

	def __repr__(self):
		t  = '== NTLMNegotiate ==\r\n'
		t += 'Signature  : %s\r\n' % repr(self.Signature)
		t += 'MessageType: %s\r\n' % repr(self.MessageType)
		t += 'NegotiateFlags: %s\r\n' % repr(self.NegotiateFlags)
		t += 'Version    : %s\r\n' % repr(self.Version)
		t += 'Domain     : %s\r\n' % repr(self.Domain)
		t += 'Workstation: %s\r\n' % repr(self.Workstation)
		
		return t
		
def test():
	test_reconstrut()
	test_construct()
	
def test_reconstrut(data = None):
	print('=== reconstruct===')
	if not data:
		nego_test_data = bytes.fromhex('4e544c4d5353500001000000978208e2000000000000000000000000000000000a00d73a0000000f')
	else:
		nego_test_data = data
	nego = NTLMNegotiate.from_bytes(nego_test_data)
	print(repr(nego))
	nego_test_data_verify = nego.to_bytes()
	assert nego_test_data == nego_test_data_verify
	
def test_construct():
	flags = NegotiateFlags.NEGOTIATE_56|NegotiateFlags.NEGOTIATE_KEY_EXCH|NegotiateFlags.NEGOTIATE_128|\
			NegotiateFlags.NEGOTIATE_VERSION|\
			NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY|\
			NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|NegotiateFlags.NEGOTIATE_NTLM|NegotiateFlags.NEGOTIATE_LM_KEY|\
			NegotiateFlags.NEGOTIATE_SIGN|NegotiateFlags.REQUEST_TARGET|NegotiateFlags.NTLM_NEGOTIATE_OEM|NegotiateFlags.NEGOTIATE_UNICODE|\
			NegotiateFlags.NEGOTIATE_OEM_WORKSTATION_SUPPLIED|NegotiateFlags.NEGOTIATE_OEM_DOMAIN_SUPPLIED
	nego = NTLMNegotiate.construct(flags, domainname = "alma.com", workstationname = "testjoe", version = Version.construct())
	nego.to_bytes()
	print(repr(nego))
	
	test_reconstrut(nego.to_bytes())
	
	flags = NegotiateFlags.NEGOTIATE_56|NegotiateFlags.NEGOTIATE_KEY_EXCH|NegotiateFlags.NEGOTIATE_128|\
			NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY|\
			NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|NegotiateFlags.NEGOTIATE_NTLM|NegotiateFlags.NEGOTIATE_LM_KEY|\
			NegotiateFlags.NEGOTIATE_SIGN|NegotiateFlags.REQUEST_TARGET|NegotiateFlags.NTLM_NEGOTIATE_OEM|NegotiateFlags.NEGOTIATE_UNICODE|\
			NegotiateFlags.NEGOTIATE_OEM_WORKSTATION_SUPPLIED|NegotiateFlags.NEGOTIATE_OEM_DOMAIN_SUPPLIED
	nego = NTLMNegotiate.construct(flags, domainname = "alma.com", workstationname = "testjoe2")
	print(nego.to_bytes())
	print(repr(nego))
	
	test_reconstrut(nego.to_bytes())
	
if __name__ == '__main__':
	test()