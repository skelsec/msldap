#
#
# This is just a simple interface to the winsspi library to support NTLM
# 
from winsspi.sspi import NTLMMSLDAPSSPI
from winsspi.common.function_defs import ISC_REQ
from msldap.authentication.ntlm.native import NTLMAUTHHandler, NTLMHandlerSettings

class MSLDAPNTLMSSPI:
	def __init__(self, settings):
		self.settings = settings
		self.mode = 'CLIENT'
		self.username = settings.username
		self.password = settings.password
		self.domain = settings.domain
		self.actual_ctx_flags = None
		self.flags = ISC_REQ.CONNECTION
		if settings.encrypt is True:
			#self.flags =  ISC_REQ.REPLAY_DETECT | ISC_REQ.CONFIDENTIALITY| ISC_REQ.USE_SESSION_KEY| ISC_REQ.INTEGRITY| ISC_REQ.SEQUENCE_DETECT| ISC_REQ.CONNECTION
			self.flags =  ISC_REQ.CONNECTION | ISC_REQ.CONFIDENTIALITY
		self.sspi = NTLMMSLDAPSSPI()

		self.seq_number = 0
		self.session_key = None
		self.ntlm_ctx = NTLMAUTHHandler(NTLMHandlerSettings(None, 'MANUAL'))
		
	@property
	def ntlmChallenge(self):
		return self.ntlm_ctx.ntlmChallenge

	def get_seq_number(self):
		return self.ntlm_ctx.get_seq_number()
		
	def signing_needed(self):
		return self.ntlm_ctx.signing_needed()

	def encryption_needed(self):
		return self.ntlm_ctx.encryption_needed()

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

	def sign(self, data, message_no = 0, direction = 'init', reset_cipher = False):
		return self.ntlm_ctx.sign(data, message_no = message_no, reset_cipher = reset_cipher)

	def verify(self, data, signature):
		return self.ntlm_ctx.verify(data, signature)
	
	def get_session_key(self):
		if not self.session_key:
			self.session_key = self.sspi.get_session_key()
		
		return self.session_key
		
	#def get_extra_info(self):
	#	return self.ntlm_ctx.get_extra_info()
		
	def is_extended_security(self):
		return self.ntlm_ctx.is_extended_security()
		
	def encrypt(self, data, message_no):
		return self.ntlm_ctx.encrypt(data, message_no)
		
	def decrypt(self, data, message_no, direction='init', auth_data=None):
		return self.ntlm_ctx.decrypt(data, message_no, direction=direction, auth_data=auth_data)
	
	async def authenticate(self, authData = None, flags = None, seq_number = 0, cb_data = None):
		if authData is None:
			try:
				data, res = self.sspi.negotiate(ctx_flags = self.flags)
				self.actual_ctx_flags = self.sspi.ctx_outflags
				self.ntlm_ctx.load_negotiate(data)
				return data, res, None
			except Exception as e:
				return None, None, e
		else:
			self.ntlm_ctx.load_challenge(authData)
			data, res = self.sspi.authenticate(authData, ctx_flags = self.flags)
			self.ntlm_ctx.load_authenticate( data)
			self.ntlm_ctx.load_sessionkey(self.get_session_key())
				
			return data, res, None
			
	