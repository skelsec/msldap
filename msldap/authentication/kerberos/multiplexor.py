
## 
##
## Interface to allow remote kerberos authentication via Multiplexor
## 
##
##
##
##
## TODO: RPC auth type is not implemented or tested!!!!

from msldap.authentication.spnego.asn1_structs import KRB5Token
from minikerberos.gssapi.gssapi import get_gssapi
from minikerberos.protocol.asn1_structs import AP_REQ, AP_REP, TGS_REP
from minikerberos.protocol.encryption import Enctype, Key, _enctype_table

from multiplexor.operator.external.sspi import KerberosSSPIClient
from multiplexor.operator import MultiplexorOperator

# SMBKerberosSSPICredential:

class SMBKerberosMultiplexor:
	def __init__(self, settings):
		self.iterations = 0
		self.settings = settings
		self.mode = 'CLIENT'
		self.ksspi = None
		self.client = None
		self.target = None
		self.gssapi = None
		self.etype = None
		self.session_key = None
		
		self.setup()
		
	def setup(self):
		return
		
	async def encrypt(self, data, message_no):
		return self.gssapi.GSS_Wrap(data, message_no)
		
	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		return self.gssapi.GSS_Unwrap(data, message_no, direction=direction, auth_data=auth_data)
	
	def get_session_key(self):
		return self.session_key
	
	async def authenticate(self, authData = None, flags = None, seq_number = 0, is_rpc = False):
		#authdata is only for api compatibility reasons
		if self.ksspi is None:
			await self.start_remote_kerberos()
		try:
			if is_rpc == True:
				raise Exception('Multiplexor kerberos for RPC is not yet implemented!')
				#if self.iterations == 0:
				#	flags = ISC_REQ.CONFIDENTIALITY | \
				#			ISC_REQ.INTEGRITY | \
				#			ISC_REQ.MUTUAL_AUTH | \
				#			ISC_REQ.REPLAY_DETECT | \
				#			ISC_REQ.SEQUENCE_DETECT|\
				#			ISC_REQ.USE_DCE_STYLE
				#			
				#
				#	#token = self.ksspi.get_ticket_for_spn(self.target, flags = flags, is_rpc = True, token_data = authData)
				#	token = await self.ksspi.authenticate(self.settings.target, flags = flags, token_data = authData)
				#	print(token.hex())
				#	self.iterations += 1
				#	return token, True
				#
				#elif self.iterations == 1:
				#	flags = ISC_REQ.USE_DCE_STYLE
				#	
				#	#token = self.ksspi.get_ticket_for_spn(self.target, flags = flags, is_rpc = True, token_data = authData)
				#	token = await self.ksspi.get_ticket_for_spn(self.settings.target, flags = flags, token_data = authData)
				#	print(token.hex())
				#	
				#	
				#	aprep = AP_REP.load(token).native
				#	
				#	subkey = Key(aprep['enc-part']['etype'], self.get_session_key())
				#	
				#	cipher_text = aprep['enc-part']['cipher']
				#	cipher = _enctype_table[aprep['enc-part']['etype']]()
				#	
				#	plaintext = cipher.decrypt(subkey, 12, cipher_text)
				#	
				#	self.gssapi = get_gssapi(subkey)
				#	
				#	self.iterations += 1
				#	return token, False
				#	
				#else:
				#	raise Exception('Multiplexor Kerberos authentication exceeded maximum iteration counts')
				
			else:
				apreq, res = await self.ksspi.authenticate(self.settings.target)
				print('MULTIPLEXOR KERBEROS SSPI, APREQ: %s ERROR: %s' % (apreq, res))
				if res is None:
					self.session_key, res = await self.ksspi.get_session_key()

				return apreq, res
		except Exception as e:
			import traceback
			traceback.print_exc()
			return None

	async def start_remote_kerberos(self):
		try:
			#print(self.settings.get_url())
			#print(self.settings.agent_id)
			self.operator = MultiplexorOperator(self.settings.get_url())
			await self.operator.connect()
			#creating virtual sspi server
			server_info = await self.operator.start_sspi(self.settings.agent_id)
			#print(server_info)

			sspi_url = 'ws://%s:%s' % (server_info['listen_ip'], server_info['listen_port'])

			#print(sspi_url)
			self.ksspi = KerberosSSPIClient(sspi_url)
			await self.ksspi.connect()
		except Exception as e:
			import traceback
			traceback.print_exc()
			return None
		