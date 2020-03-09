
import os
import struct
import hmac
import copy

#from aiosmb.commons.connection.credential import SMBNTLMCredential
#from aiosmb.commons.serverinfo import NTLMServerInfo
from msldap.authentication.ntlm.templates.server import NTLMServerTemplates
from msldap.authentication.ntlm.templates.client import NTLMClientTemplates
from msldap.authentication.ntlm.structures.negotiate_flags import NegotiateFlags
from msldap.authentication.ntlm.structures.version import Version
from msldap.authentication.ntlm.structures.ntlmssp_message_signature import NTLMSSP_MESSAGE_SIGNATURE
from msldap.authentication.ntlm.structures.ntlmssp_message_signature_noext import NTLMSSP_MESSAGE_SIGNATURE_NOEXT
from msldap.authentication.ntlm.messages.negotiate import NTLMNegotiate
from msldap.authentication.ntlm.messages.challenge import NTLMChallenge
from msldap.authentication.ntlm.messages.authenticate import NTLMAuthenticate
from msldap.authentication.ntlm.creds_calc import *
from msldap.crypto.symmetric import RC4
		

class NTLMHandlerSettings:
	def __init__(self, credential, mode = 'CLIENT', template_name = 'Windows10_15063', custom_template = None):
		self.credential = credential
		self.mode = mode
		self.template_name = template_name
		self.custom_template = custom_template #for custom templates, must be dict
		
		self.template = None
		self.ntlm_downgrade = False
		
		self.construct_message_template()
		
	def construct_message_template(self):
		if self.mode.upper() == 'MANUAL':
			return
			
		if not self.template_name:
			if not self.custom_template:
				raise Exception('No NTLM tamplate specified!')
			
			self.template = self.custom_template
		
		if self.mode.upper() == 'SERVER':
			if self.template_name in NTLMServerTemplates:
				self.template = NTLMServerTemplates[self.template_name]
			else:
				raise Exception('No NTLM server template found with name %s' % self.template_name)
	
		else:
			if self.template_name in NTLMClientTemplates:
				self.template = NTLMClientTemplates[self.template_name]
				if 'ntlm_downgrade' in self.template:
					self.ntlm_downgrade = self.template['ntlm_downgrade']
			else:
					raise Exception('No NTLM server template found with name %s' % self.template_name)
		

class NTLMAUTHHandler:
	def __init__(self, settings):
		self.settings = settings #NTLMHandlerSettings		
		
		self.mode = None
		self.flags = None
		self.challenge = None
		
		self.ntlmNegotiate     = None #ntlm Negotiate message from client
		self.ntlmChallenge     = None #ntlm Challenge message to client
		self.ntlmAuthenticate  = None #ntlm Authenticate message from client
		
		self.ntlmNegotiate_raw     = None #message as bytes, as it's recieved/sent
		self.ntlmChallenge_raw     = None #message as bytes, as it's recieved/sent
		self.ntlmAuthenticate_raw  = None #message as bytes, as it's recieved/sent

		
		self.EncryptedRandomSessionKey = None
		self.RandomSessionKey = None
		self.SessionBaseKey = None
		self.KeyExchangeKey = None
		
		self.SignKey_client = None
		self.SealKey_client = None
		self.SignKey_server = None
		self.SealKey_server = None

		self.crypthandle_client = None
		self.crypthandle_server = None
		self.signhandle_server = None
		self.signhandle_client = None
		
		
		self.iteration_cnt = 0
		self.ntlm_credentials = None
		self.timestamp = None #used in unittest only!
		self.extra_info = None
		self.setup()

	def setup(self):
		self.mode = self.settings.mode
		if self.mode.upper() == 'MANUAL':
			#for passign the messages automatically with the sessionbasekey, the using this class for sign and seal
			return
		
		if 'challenge' not in self.settings.template:
			self.challenge = os.urandom(8)
		else:
			self.challenge = self.settings.template['challenge']
		self.flags = self.settings.template['flags']
		if 'session_key' in self.settings.template:
			self.RandomSessionKey = self.settings.template['session_key']
		
		self.timestamp = self.settings.template.get('timestamp') #used in unittest only!
		
					
		if self.mode.upper() == 'SERVER':
			version    = self.settings.template['version']
			targetName = self.settings.template['targetname']
			targetInfo = self.settings.template['targetinfo']

			self.ntlmChallenge = NTLMChallenge.construct(challenge = self.challenge, targetName = targetName, targetInfo = targetInfo, version = version, flags = self.flags)
		
		#else:
		#	domainname = self.settings.template['domain_name']
		#	workstationname = self.settings.template['workstation_name']
		#	version = self.settings.template.get('version')
			
	def load_negotiate(self, data):
		self.ntlmNegotiate = NTLMNegotiate.from_bytes(data)
	
	def load_challenge(self, data):
		self.ntlmChallenge = NTLMChallenge.from_bytes(data)
		
	def load_authenticate(self, data):
		self.ntlmAuthenticate = NTLMAuthenticate.from_bytes(data)
		
	def load_sessionkey(self, data):
		self.RandomSessionKey = data
		self.setup_crypto()
	
	def set_sign(self, tf = True):
		if tf == True:
			self.flags |= NegotiateFlags.NEGOTIATE_SIGN
		else:
			self.flags &= ~NegotiateFlags.NEGOTIATE_SIGN
			
	def set_seal(self, tf = True):
		if tf == True:
			self.flags |= NegotiateFlags.NEGOTIATE_SEAL
		else:
			self.flags &= ~NegotiateFlags.NEGOTIATE_SEAL
			
	def set_version(self, tf = True):
		if tf == True:
			self.flags |= NegotiateFlags.NEGOTIATE_VERSION
		else:
			self.flags &= ~NegotiateFlags.NEGOTIATE_VERSION
			
	def is_extended_security(self):
		return NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY in self.ntlmChallenge.NegotiateFlags
	
	#def get_extra_info(self):
	#	self.extra_info = NTLMServerInfo.from_challenge(self.ntlmChallenge)
	#	return self.extra_info
		
	def MAC(self, handle, signingKey, seqNum, message):
		if self.is_extended_security() == True:
			msg = NTLMSSP_MESSAGE_SIGNATURE()
			if NegotiateFlags.NEGOTIATE_KEY_EXCH in self.ntlmChallenge.NegotiateFlags:
				tt = struct.pack('<i', seqNum) + message
				t = hmac_md5(signingKey)
				t.update(tt)
				
				msg.Checksum = handle(t.digest()[:8])
				msg.SeqNum = seqNum
				seqNum += 1
			else:
				t = hmac_md5(signingKey)
				t.update(struct.pack('<i',seqNum)+message)
				msg.Checksum = t.digest()[:8]
				msg.SeqNum = seqNum
				seqNum += 1
				
		else:
			raise Exception('Not implemented!')
			#t = struct.pack('<I',binascii.crc32(message)& 0xFFFFFFFF)
			#randompad = 0
			#msg = NTLMSSP_MESSAGE_SIGNATURE_NOEXT()
			#msg.RandomPad = handle(struct.pack('<I',randompad))
			#msg.Checksum = struct.unpack('<I',handle(messageSignature['Checksum']))[0]
			
		return msg.to_bytes()
	
	#async def sign(self, data, message_no, direction=None):
	#	return self.SIGN(self.SignKey_client, data, message_no, RC4(self.SignKey_client).encrypt )

	async def encrypt(self, data, sequence_no):
		return self.SEAL(
			self.SignKey_client, 
			self.SealKey_client, 
			data, 
			data, 
			sequence_no, 
			self.crypthandle_client.encrypt
		)

	async def decrypt(self, data, sequence_no, direction='init', auth_data=None):		
		data = data[16:]
		msg_struct, signature = self.SEAL(
			self.SignKey_server, 
			self.SealKey_server, 
			data, 
			data, 
			sequence_no, 
			self.crypthandle_server.encrypt
		)
		print(data[:16])
		print(signature)
		return msg_struct

	async def sign(self, data, message_no, direction=None):
		return self.SIGN(
			self.SealKey_client,
			data,
			message_no,
			self.signhandle_client.encrypt
		)

	def SEAL(self, signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, cipher_encrypt):
		sealedMessage = cipher_encrypt(messageToEncrypt)
		signature = self.MAC(cipher_encrypt, signingKey, seqNum, messageToSign)
		return sealedMessage, signature
		
	def SIGN(self, signingKey, message, seqNum, cipher_encrypt):
		return self.MAC(cipher_encrypt, signingKey, seqNum, message)
	
	def signing_needed(self):
		return (
			NegotiateFlags.NEGOTIATE_SIGN in self.ntlmChallenge.NegotiateFlags or \
			NegotiateFlags.NEGOTIATE_SEAL in self.ntlmChallenge.NegotiateFlags
		)
	
	def encryption_needed(self):
		return NegotiateFlags.NEGOTIATE_SEAL in self.ntlmChallenge.NegotiateFlags

	def calc_sealkey(self, mode = 'Client'):
		if NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY in self.ntlmChallenge.NegotiateFlags:
			if NegotiateFlags.NEGOTIATE_128 in self.ntlmChallenge.NegotiateFlags:
				sealkey = self.RandomSessionKey
			elif NegotiateFlags.NEGOTIATE_56 in self.ntlmChallenge.NegotiateFlags:
				sealkey = self.RandomSessionKey[:7]
			else:
				sealkey = self.RandomSessionKey[:5]
				
			if mode == 'Client':
				md5 = hashlib.new('md5')
				md5.update(sealkey + b'session key to client-to-server sealing key magic constant\x00')
				sealkey = md5.digest()
			else:
				md5 = hashlib.new('md5')
				md5.update(sealkey + b'session key to server-to-client sealing key magic constant\x00')
				sealkey = md5.digest()
				
		elif NegotiateFlags.NEGOTIATE_56 in self.ntlmChallenge.NegotiateFlags:
			sealkey = self.RandomSessionKey[:7] + b'\xa0'
		else:
			sealkey = self.RandomSessionKey[:5] + b'\xe5\x38\xb0'
			
		if mode == 'Client':
			self.SealKey_client = sealkey
			if sealkey is not None:
				self.crypthandle_client = RC4(self.SealKey_client)
		else:
			self.SealKey_server = sealkey
			if sealkey is not None:
				self.crypthandle_server = RC4(self.SealKey_server)
			
		return sealkey
		
	def calc_signkey(self, mode = 'Client'):
		if NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY in self.ntlmChallenge.NegotiateFlags:
			if mode == 'Client':
				md5 = hashlib.new('md5')
				md5.update(self.RandomSessionKey + b"session key to client-to-server signing key magic constant\x00")
				signkey = md5.digest()
			else:
				md5 = hashlib.new('md5')
				md5.update(self.RandomSessionKey + b"session key to server-to-client signing key magic constant\x00")
				signkey = md5.digest()
		else:
			signkey = None
			
		if mode == 'Client':
			self.SignKey_client = signkey
			if signkey is not None:
				self.signhandle_client = RC4(self.SealKey_client)

		else:
			self.SignKey_server = signkey
			if signkey is not None:
				self.signhandle_server = RC4(self.SignKey_server)
		
		return signkey
		
	def get_session_key(self):
		return self.RandomSessionKey
		
	def get_sealkey(self, mode = 'Client'):
		if mode == 'Client':
			return self.SealKey_client
		else:
			return self.SealKey_server
			
	def get_signkey(self, mode = 'Client'):
		if mode == 'Client':
			return self.SignKey_client
		else:
			return self.SignKey_server
		
	def setup_crypto(self):
		if not self.RandomSessionKey:
			self.RandomSessionKey = os.urandom(16)
		
		if self.mode.upper() != 'MANUAL':
			#this check is here to provide the option to load the messages + the sessionbasekey manually
			#then you will be able to use the sign and seal functions provided by this class
			self.SessionBaseKey = self.ntlm_credentials.SessionBaseKey
		
			rc4 = RC4(self.KeyExchangeKey)
			self.EncryptedRandomSessionKey = rc4.encrypt(self.RandomSessionKey)
		
		self.calc_sealkey('Client')
		self.calc_sealkey('Server')
		self.calc_signkey('Client')
		self.calc_signkey('Server')

	async def authenticate(self, authData, flags = None, seq_number = 0, is_rpc = False):
		if self.mode.upper() == 'SERVER':
			if self.ntlmNegotiate is None:
				###parse client NTLMNegotiate message
				self.ntlmNegotiate = NTLMNegotiate.from_bytes(authData)
				return self.ntlmChallenge.to_bytes(), True 

			elif self.ntlmAuthenticate is None:
				self.ntlmAuthenticate = NTLMAuthenticate.from_bytes(authData, self.use_NTLMv2)
				creds = NTLMcredential.construct(self.ntlmNegotiate, self.ntlmChallenge, self.ntlmAuthenticate)
				print(creds)

				# TODO: check when is sessionkey needed and check when is singing needed, and calculate the keys!
				# self.calc_SessionBaseKey()
				# self.calc_KeyExchangeKey()
				auth_credential = creds[0]
				#self.SessionBaseKey = auth_credential.calc_session_base_key()
				#self.calc_key_exchange_key()

				if auth_credential.verify(self.credential):
					return False, auth_credential
				else:
					return False, auth_credential

			else:
				raise Exception('Too many calls to do_AUTH function!')
				
		elif self.mode.upper() == 'CLIENT':
			if self.iteration_cnt == 0:
				if authData is not None:
					raise Exception('First call as client MUST be with empty data!')
					
				if is_rpc == True:
					#rpc (unknow reason) reqauires seal to be set, otherwise it will fail to authenticate
					self.set_seal()
				
				self.iteration_cnt += 1
				#negotiate message was already calulcated in setup
				self.ntlmNegotiate = NTLMNegotiate.construct(self.flags, domainname = self.settings.template['domain_name'], workstationname = self.settings.template['workstation_name'], version = self.settings.template.get('version'))			
				self.ntlmNegotiate_raw = self.ntlmNegotiate.to_bytes()
				return self.ntlmNegotiate_raw, True
				
			else:
				#server challenge incoming
				self.ntlmChallenge_raw = authData
				self.ntlmChallenge = NTLMChallenge.from_bytes(authData)
				
				
				if is_rpc == True:
					#rpc (unknow reason) reqauires seal to be set, otherwise it will fail to authenticate
					self.set_seal()
				
				##################self.flags = self.ntlmChallenge.NegotiateFlags
				
				#we need to calculate the response based on the credential and the settings flags
				if self.settings.ntlm_downgrade == True:
					#NTLMv1 authentication
					# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
					
					#check if we authenticate as guest
					if self.settings.credential.is_guest == True:
						lmresp = LMResponse()
						lmresp.Response = b'\x00'
						self.ntlmAuthenticate = NTLMAuthenticate.construct(self.flags, lm_response= lmresp)
						return self.ntlmAuthenticate.to_bytes(), False
						
					if self.flags & NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY:
						#Extended auth!
						self.ntlm_credentials = netntlm_ess.construct(self.ntlmChallenge.ServerChallenge, self.challenge, self.settings.credential)
						
						self.KeyExchangeKey = self.ntlm_credentials.calc_key_exchange_key()						
						self.setup_crypto()
						
						self.ntlmAuthenticate = NTLMAuthenticate.construct(self.flags, lm_response= self.ntlm_credentials.LMResponse, nt_response = self.ntlm_credentials.NTResponse, version = self.ntlmNegotiate.Version, encrypted_session = self.EncryptedRandomSessionKey)
					else:
						self.ntlm_credentials = netntlm.construct(self.ntlmChallenge.ServerChallenge, self.settings.credential)
						
						self.KeyExchangeKey = self.ntlm_credentials.calc_key_exchange_key(with_lm = self.flags & NegotiateFlags.NEGOTIATE_LM_KEY, non_nt_session_key = self.flags & NegotiateFlags.REQUEST_NON_NT_SESSION_KEY)						
						self.setup_crypto()
						self.ntlmAuthenticate = NTLMAuthenticate.construct(self.flags, lm_response= self.ntlm_credentials.LMResponse, nt_response = self.ntlm_credentials.NTResponse, version = self.ntlmNegotiate.Version, encrypted_session = self.EncryptedRandomSessionKey)

							
							
				else:
					#NTLMv2
					# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
					if self.settings.credential.is_guest == True:
						lmresp = LMResponse()
						lmresp.Response = b'\x00'
						self.ntlmAuthenticate = NTLMAuthenticate.construct(self.flags, lm_response= lmresp)
						return self.ntlmAuthenticate.to_bytes(), False
						
					else:
						#comment this out for testing!
						ti = self.ntlmChallenge.TargetInfo
						ti[AVPAIRType.MsvAvTargetName] = 'cifs/%s' % ti[AVPAIRType.MsvAvNbComputerName]
						###
						
						self.ntlm_credentials = netntlmv2.construct(self.ntlmChallenge.ServerChallenge, self.challenge, ti, self.settings.credential, timestamp = self.timestamp)
						self.KeyExchangeKey = self.ntlm_credentials.calc_key_exchange_key()						
						self.setup_crypto()
						
						#TODO: if "ti" / targetinfo in the challenge message has "MsvAvFlags" type and the bit for MIC is set (0x00000002) we need to send a MIC. probably...
						mic = None
						
						self.ntlmAuthenticate = NTLMAuthenticate.construct(self.flags, domainname= self.settings.credential.domain, workstationname= self.settings.credential.workstation, username= self.settings.credential.username, lm_response= self.ntlm_credentials.LMResponse, nt_response= self.ntlm_credentials.NTResponse, version = self.ntlmNegotiate.Version, encrypted_session = self.EncryptedRandomSessionKey, mic = mic)
						
				self.ntlmAuthenticate_raw = self.ntlmAuthenticate.to_bytes()
				return self.ntlmAuthenticate_raw, False
				
		elif self.mode.upper() == 'RELAY':
			if self.iteration_cnt == 0:
				self.ntlmNegotiate_raw = authData
				self.ntlmNegotiate = NTLMNegotiate.from_bytes(authData)	
				self.iteration_cnt += 1
			
			elif self.iteration_cnt == 1:
				self.ntlmChallenge_raw = authData
				self.ntlmChallenge = NTLMChallenge.from_bytes(authData)
				self.iteration_cnt += 1
			
			elif self.iteration_cnt == 2:
				self.ntlmChallenge_raw = authData
				self.ntlmChallenge = NTLMChallenge.from_bytes(authData)
				self.iteration_cnt += 1
				
			else:
				raise Exception('Too many iterations for relay mode!')
				


#def test_msdn():
#	credential = Credential()
#	credential.username = 'User'
#	credential.domain = 'Domain'
#	credential.password = 'Password'
#	
#	template = {
#			'flags'            :  NegotiateFlags.NEGOTIATE_56|
#								  NegotiateFlags.REQUEST_NON_NT_SESSION_KEY|
#								  NegotiateFlags.NEGOTIATE_KEY_EXCH|
#								  NegotiateFlags.NEGOTIATE_128|
#								  NegotiateFlags.NEGOTIATE_VERSION|
#								  NegotiateFlags.TARGET_TYPE_SERVER|
#								  NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|
#								  NegotiateFlags.NEGOTIATE_NTLM|
#								  NegotiateFlags.NEGOTIATE_SIGN|
#								  NegotiateFlags.NEGOTIATE_SEAL|
#								  NegotiateFlags.NTLM_NEGOTIATE_OEM|
#								  NegotiateFlags.NEGOTIATE_UNICODE,
#			'version'          : Version.construct(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_10, minor = WindowsMinorVersion.WINDOWS_MINOR_VERSION_0, build = 15063 ),
#			'domain_name'      : 'Domain',
#			'workstation_name' : 'COMPUTER',
#			'ntlm_downgrade'   : True,
#			'extended_security': False
#	}
#	settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = None, ntlm_downgrade = True, extended_security = False, custom_template = template)
#	handler = NTLMAUTHHandler(settings)
#	#assert handler.flags == int.from_bytes(b'\x33\x82\x02\xe2', "little", signed = False)
#	data, is_res = handler.authenticate(None)
#	print(data)
#	print(is_res)
#	
#	details = AVPairs({AVPAIRType.MsvAvNbDomainName: 'TEST', AVPAIRType.MsvAvNbComputerName: 'WIN2019AD', AVPAIRType.MsvAvDnsDomainName: 'test.corp', AVPAIRType.MsvAvDnsComputerName: 'WIN2019AD.test.corp', AVPAIRType.MsvAvTimestamp: b'\xae\xc6\x00\xbf\xc5\xfd\xd4\x01', AVPAIRType.MsvAvFlags: b'\x02\x00\x00\x00', AVPAIRType.MsvAvSingleHost: b"0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00R}'\xf24\xdet7`\x96c\x84\xd3oa\xae*\xa4\xfc*8\x06\x99\xf8\xca\xa6\x00\x01\x1bHm\x89", AVPAIRType.MsvChannelBindings: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', AVPAIRType.MsvAvTargetName: 'cifs/10.10.10.2'})
#	
#	challenge = NTLMChallenge.construct(challenge=b'\x01\x23\x45\x67\x89\xab\xcd\xef', targetName = 'Domain', targetInfo = details, version = handler.ntlmNegotiate.Version, flags= handler.flags)
#	data, is_res = handler.authenticate(challenge.to_bytes())
#	print(data)
#	print(is_res)
#	
#	print(handler.ntlmAuthenticate.LMChallenge.to_bytes().hex())
#	print(handler.ntlmAuthenticate.NTChallenge.to_bytes().hex())
#	
#
#def test():
#	template_name = 'Windows10_15063'
#	credential = Credential()
#	credential.username = 'test'
#	credential.password = 'test'
#	
#	settings = NTLMHandlerSettings(credential, mode = 'CLIENT', template_name = template_name, ntlm_downgrade = False, extended_security = True)
#	handler = NTLMAUTHHandler(settings)
#	data, is_res = handler.authenticate(None)
#	print(data)
#	print(is_res)
#	
#if __name__ == '__main__':
#	from aiosmb.ntlm.structures.version import Version, WindowsMajorVersion, WindowsMinorVersion
#	test_msdn()