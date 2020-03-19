#
# This is just a simple interface to the winsspi library to support Kerberos
# Will only work on windows, ovbiously
# 
#
#

from msldap.authentication.spnego.asn1_structs import KRB5Token
from winsspi.sspi import KerberosMSLDAPSSPI
from winsspi.common.function_defs import ISC_REQ
from minikerberos.gssapi.gssapi import get_gssapi
from minikerberos.protocol.asn1_structs import AP_REQ, AP_REP
from minikerberos.protocol.encryption import Enctype, Key, _enctype_table

class MSLDAPKerberosSSPI:
	def __init__(self, settings):
		self.iterations = 0
		self.settings = settings
		self.username = settings.username
		self.password = settings.password
		self.domain = settings.domain
		self.actual_ctx_flags = None #this will be popilated by the output of get_ticket_for_spn
		self.flags = ISC_REQ.CONNECTION
		if settings.channelbind is True:
			#self.flags =  ISC_REQ.REPLAY_DETECT | ISC_REQ.CONFIDENTIALITY| ISC_REQ.USE_SESSION_KEY| ISC_REQ.INTEGRITY| ISC_REQ.SEQUENCE_DETECT| ISC_REQ.CONNECTION
			self.flags =  ISC_REQ.CONNECTION | ISC_REQ.CONFIDENTIALITY
		self.ksspi = None
		self.spn = settings.spn
		self.gssapi = None
		self.etype = None
		self.session_key = None
	
	
	def signing_needed(self):
		return ISC_REQ.INTEGRITY in self.actual_ctx_flags

	def encryption_needed(self):
		return ISC_REQ.CONFIDENTIALITY in self.actual_ctx_flags
	
	async def encrypt(self, data, message_no):
		return self.gssapi.GSS_Wrap(data, message_no)
		
	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		return self.gssapi.GSS_Unwrap(data, message_no, direction=direction, auth_data=auth_data)
	
	def get_session_key(self):
		if self.session_key is None:
			self.session_key = self.ksspi.get_session_key()
		return self.session_key
	
	async def authenticate(self, authData = None, flags = None, seq_number = 0, is_rpc = False):
		try:
			self.ksspi = KerberosMSLDAPSSPI(domain = self.domain, username=self.username, password=self.password)
			token, self.actual_ctx_flags = self.ksspi.get_ticket_for_spn(self.spn, ctx_flags = self.flags)
			apreq = AP_REQ.load(token).native
			subkey = Key(apreq['ticket']['enc-part']['etype'], self.get_session_key())
			self.gssapi = get_gssapi(subkey)
			print(type(self.gssapi))
			print(self.actual_ctx_flags)
			return token, False
		except:
			import traceback
			traceback.print_exc()
		