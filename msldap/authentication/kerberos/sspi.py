#
# This is just a simple interface to the winsspi library to support Kerberos
# Will only work on windows, ovbiously
# 
#
#

from msldap.authentication.spnego.asn1_structs import KRB5Token
from winsspi.sspi import KerberosSMBSSPI
from winsspi.common.function_defs import ISC_REQ
from minikerberos.gssapi.gssapi import get_gssapi
from minikerberos.protocol.asn1_structs import AP_REQ, AP_REP
from minikerberos.protocol.encryption import Enctype, Key, _enctype_table

class MSLDAPKerberosSSPI:
	def __init__(self, settings):
		self.iterations = 0
		self.settings = settings
		self.mode = 'CLIENT'
		self.ksspi = KerberosSMBSSPI()
		self.client = None
		self.target = None
		self.gssapi = None
		self.etype = None
		
		self.setup()
		
	def setup(self):
		self.mode = self.settings.mode
		self.client = self.settings.client
		self.target = self.settings.target
		
	async def encrypt(self, data, message_no):
		return self.gssapi.GSS_Wrap(data, message_no)
		
	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		return self.gssapi.GSS_Unwrap(data, message_no, direction=direction, auth_data=auth_data)
	
	def get_session_key(self):
		return self.ksspi.get_session_key()
	
	async def authenticate(self, authData = None, flags = None, seq_number = 0, is_rpc = False):
		#authdata is only for api compatibility reasons
		if is_rpc == True:
			if self.iterations == 0:
				flags = ISC_REQ.CONFIDENTIALITY | \
						ISC_REQ.INTEGRITY | \
						ISC_REQ.MUTUAL_AUTH | \
						ISC_REQ.REPLAY_DETECT | \
						ISC_REQ.SEQUENCE_DETECT|\
						ISC_REQ.USE_DCE_STYLE
						

				token = self.ksspi.get_ticket_for_spn(self.target, flags = flags, is_rpc = True, token_data = authData)
				#print(token.hex())
				self.iterations += 1
				return token, True
			
			elif self.iterations == 1:
				flags = ISC_REQ.USE_DCE_STYLE
						
				token = self.ksspi.get_ticket_for_spn(self.target, flags = flags, is_rpc = True, token_data = authData)
				#print(token.hex())
				
				
				aprep = AP_REP.load(token).native
				
				subkey = Key(aprep['enc-part']['etype'], self.get_session_key())
				
				cipher_text = aprep['enc-part']['cipher']
				cipher = _enctype_table[aprep['enc-part']['etype']]()
				
				plaintext = cipher.decrypt(subkey, 12, cipher_text)
				
				self.gssapi = get_gssapi(subkey)
				
				self.iterations += 1
				return token, False
				
			else:
				raise Exception('SSPI Kerberos -RPC - auth encountered too many calls for authenticate.')
			
		else:
			apreq = self.ksspi.get_ticket_for_spn(self.target)
			return apreq, False
		