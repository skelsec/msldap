#
#
# Interface to support remote authentication via multiplexor
# 
# Connects to the multiplexor server, and starts an SSPI server locally for the specific agentid
# SSPI server will be used to perform NTLM authentication remotely,
# while constructing a local NTLM authentication object
# After the auth finishes, it also grabs the sessionkey.
# The NTLM object can be used in future operations (encrypt/decrypt/sign) locally 
# without the need of future remote calls 
#

from msldap import logger
from msldap.authentication.ntlm.native import NTLMAUTHHandler, NTLMHandlerSettings
from multiplexor.operator.external.sspi import SSPINTLMClient
from multiplexor.operator import MultiplexorOperator
import enum

class ISC_REQ(enum.IntFlag):
	DELEGATE = 1
	MUTUAL_AUTH = 2
	REPLAY_DETECT = 4
	SEQUENCE_DETECT = 8
	CONFIDENTIALITY = 16
	USE_SESSION_KEY = 32
	PROMPT_FOR_CREDS = 64
	USE_SUPPLIED_CREDS = 128
	ALLOCATE_MEMORY = 256
	USE_DCE_STYLE = 512
	DATAGRAM = 1024
	CONNECTION = 2048
	CALL_LEVEL = 4096
	FRAGMENT_SUPPLIED = 8192
	EXTENDED_ERROR = 16384
	STREAM = 32768
	INTEGRITY = 65536
	IDENTIFY = 131072
	NULL_SESSION = 262144
	MANUAL_CRED_VALIDATION = 524288
	RESERVED1 = 1048576
	FRAGMENT_TO_FIT = 2097152
	HTTP = 0x10000000

#
#
# Interface to support remote authentication via multiplexor
# 
# Connects to the multiplexor server, and starts an SSPI server locally for the specific agentid
# SSPI server will be used to perform NTLM authentication remotely,
# while constructing a local NTLM authentication object
# After the auth finishes, it also grabs the sessionkey.
# The NTLM object can be used in future operations (encrypt/decrypt/sign) locally 
# without the need of future remote calls 
#

class MSLDAPNTLMMultiplexor:
	def __init__(self, settings):
		self.settings = settings
		self.mode = None #'CLIENT'
		self.sspi = None
		self.operator = None
		self.client = None
		self.target = None
		self.seq_number = 0
		
		self.session_key = None
		self.ntlm_ctx = NTLMAUTHHandler(NTLMHandlerSettings(None, 'MANUAL'))

	def setup(self):
		return
		
	@property
	def ntlmChallenge(self):
		return self.ntlm_ctx.ntlmChallenge
		
	def get_sealkey(self, mode = 'Client'):
		return self.ntlm_ctx.get_sealkey(mode = mode)
			
	def get_signkey(self, mode = 'Client'):
		return self.ntlm_ctx.get_signkey(mode = mode)
	
	def get_session_key(self):
		return self.session_key
		
	def is_extended_security(self):
		return self.ntlm_ctx.is_extended_security()

	def get_seq_number(self):
		return self.seq_number

	def signing_needed(self):
		return self.ntlm_ctx.signing_needed()
	
	def encryption_needed(self):
		return self.ntlm_ctx.encryption_needed()
		
	async def encrypt(self, data, message_no):
		return await self.ntlm_ctx.encrypt(data, message_no)
		
	async def decrypt(self, data, sequence_no, direction='init', auth_data=None):
		return await self.ntlm_ctx.decrypt(data, sequence_no, direction=direction, auth_data=auth_data)

	async def sign(self, data, message_no, direction=None, reset_cipher = False):
		return await self.ntlm_ctx.sign(data, message_no, direction=None, reset_cipher = reset_cipher)
	
	async def authenticate(self, authData = None, flags = None, seq_number = 0, cb_data=None):
		is_rpc = False
		if self.sspi is None:
			res, err = await self.start_remote_sspi()
			if err is not None:
				return None, None, err

		if is_rpc is True and flags is None:
			flags = ISC_REQ.REPLAY_DETECT | ISC_REQ.CONFIDENTIALITY| ISC_REQ.USE_SESSION_KEY| ISC_REQ.INTEGRITY| ISC_REQ.SEQUENCE_DETECT| ISC_REQ.CONNECTION
			flags = int(flags)
		
		if authData is None:
			data, res = await self.sspi.authenticate(flags = flags)
			if res is None:
				self.ntlm_ctx.load_negotiate(data)
			return data, res, None
		else:
			self.ntlm_ctx.load_challenge( authData)
			data, res = await self.sspi.challenge(authData, flags = flags)
			if res is None:
				self.ntlm_ctx.load_authenticate( data)
				self.session_key, res = await self.sspi.get_session_key()
				if res is None:
					self.ntlm_ctx.load_sessionkey(self.get_session_key())
				
			return data, res, None


	async def start_remote_sspi(self):
		try:
			#print(self.settings.get_url())
			self.operator = MultiplexorOperator(self.settings.get_url(), logging_sink=logger)
			await self.operator.connect()
			#creating virtual sspi server
			server_info = await self.operator.start_sspi(self.settings.agent_id)
			#print(server_info)

			sspi_url = 'ws://%s:%s' % (server_info['listen_ip'], server_info['listen_port'])

			#print(sspi_url)
			self.sspi = SSPINTLMClient(sspi_url)
			await self.sspi.connect()
			return True, None
		except Exception as e:
			import traceback
			traceback.print_exc()
			return None, e
			
	