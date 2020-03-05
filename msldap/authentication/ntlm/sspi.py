#
#
# This is just a simple interface to the winsspi library to support NTLM
# 
from winsspi.sspi import NTLMSMBSSPI
from msldap.authentication.ntlm.native import NTLMAUTHHandler, NTLMHandlerSettings

class MSLDAPNTLMSSPI:
	def __init__(self, settings):
		self.settings = settings
		self.mode = None #'CLIENT'
		self.sspi = NTLMSMBSSPI()
		self.client = None
		self.target = None
		#self.ntlmChallenge = None
		
		self.session_key = None
		self.ntlm_ctx = NTLMAUTHHandler(NTLMHandlerSettings(None, 'MANUAL'))
		
		self.setup()
		
	@property
	def ntlmChallenge(self):
		return self.ntlm_ctx.ntlmChallenge
		
	def setup(self):
		self.mode = self.settings.mode.upper()
		self.client = self.settings.client
		self.password = self.settings.password
		
	def get_sealkey(self, mode = 'Client'):
		return self.ntlm_ctx.get_sealkey(mode = mode)
			
	def get_signkey(self, mode = 'Client'):
		return self.ntlm_ctx.get_signkey(mode = mode)
	
	#def wrap(self, data, sequence_no):
	#	self.ntlm_ctx.wrap()
	
	def unwrap(self, data):
		return self.ntlm_ctx.unwrap(data)
		
	def SEAL(self, signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, cipher_encrypt):
		return self.ntlm_ctx.SEAL(signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, cipher_encrypt)
		
	def SIGN(self, signingKey, message, seqNum, cipher_encrypt):
		return self.ntlm_ctx.SIGN(signingKey, message, seqNum, cipher_encrypt)
	
	def get_session_key(self):
		if not self.session_key:
			self.session_key = self.sspi.get_session_key()
		
		return self.session_key
		
	#def get_extra_info(self):
	#	return self.ntlm_ctx.get_extra_info()
		
	def is_extended_security(self):
		return self.ntlm_ctx.is_extended_security()
		
	async def encrypt(self, data, message_no):
		return self.sspi.encrypt(data, message_no)
		
	async def decrypt(self, data, message_no):
		return self.sspi.decrypt(data, message_no)
	
	async def authenticate(self, authData = None, flags = None, seq_number = 0, is_rpc = False):
		if self.mode == 'CLIENT':
			if authData is None:
				data, res = self.sspi.negotiate(is_rpc = is_rpc)
				self.ntlm_ctx.load_negotiate(data)
				return data, res
			else:
				self.ntlm_ctx.load_challenge( authData)
				data, res = self.sspi.authenticate(authData, is_rpc = is_rpc)
				self.ntlm_ctx.load_authenticate( data)
				self.ntlm_ctx.load_sessionkey(self.get_session_key())
				
				return data, res
			
	