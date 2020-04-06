#
# This is just a simple interface to the winsspi library to support Kerberos
# Will only work on windows, ovbiously
# 
#
#

from msldap.authentication.spnego.asn1_structs import KRB5Token
from winsspi.sspi import KerberosMSLDAPSSPI
from winsspi.common.function_defs import ISC_REQ, GetSequenceNumberFromEncryptdataKerberos
from msldap.authentication.kerberos.gssapi import get_gssapi, GSSWrapToken
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
		if settings.encrypt is True:
			self.flags =  ISC_REQ.CONFIDENTIALITY| ISC_REQ.INTEGRITY | ISC_REQ.CONNECTION #| ISC_REQ.MUTUAL_AUTH #| ISC_REQ.USE_DCE_STYLE
		self.ksspi = None
		self.spn = settings.spn
		self.gssapi = None
		self.etype = None
		self.session_key = None
		self.seq_number = None
	
	def get_seq_number(self):
		"""
		Fetches the starting sequence number. This is either zero or can be found in the authenticator field of the 
		AP_REQ structure. As windows uses a random seq number AND a subkey as well, we can't obtain it by decrypting the 
		AP_REQ structure. Insead under the hood we perform an encryption operation via EncryptMessage API which will 
		yield the start sequence number
		"""
		if self.seq_number is not None:
			return self.seq_number
		if ISC_REQ.CONFIDENTIALITY in self.actual_ctx_flags:
			self.seq_number = GetSequenceNumberFromEncryptdataKerberos(self.ksspi.context)
		if self.seq_number is None:
			self.seq_number = 0

		return self.seq_number

	def signing_needed(self):
		"""
		Checks if integrity protection was enabled
		"""
		return ISC_REQ.INTEGRITY in self.actual_ctx_flags

	def encryption_needed(self):
		"""
		Checks if confidentiality was enabled
		"""
		return ISC_REQ.CONFIDENTIALITY in self.actual_ctx_flags

	async def sign(self, data, message_no, direction = 'init'):
		"""
		Signs a message. 
		"""
		return self.gssapi.GSS_GetMIC(data, message_no, direction = direction)	
	
	async def encrypt(self, data, message_no):
		"""
		Encrypts a message. 
		"""
		return self.gssapi.GSS_Wrap(data, message_no)
		
	async def decrypt(self, data, message_no, direction='init'):
		"""
		Decrypts message. Also performs integrity checking.
		"""
		return self.gssapi.GSS_Unwrap(data, message_no, direction=direction)
	
	def get_session_key(self):
		"""
		Fetches the session key. Under the hood this uses QueryContextAttributes API call.
		This will fail if the authentication is not yet finished!
		"""
		err = None
		if self.session_key is None:
			self.session_key, err = self.ksspi.get_session_key()
		return self.session_key, err
	
	async def authenticate(self, authData = None, flags = None, seq_number = 0, cb_data = None):
		"""
		This function is called (multiple times depending on the flags) to perform authentication. 
		"""
		try:
			if self.iterations == 0:
				self.ksspi = KerberosMSLDAPSSPI(domain = self.domain, username=self.username, password=self.password)				
				token, self.actual_ctx_flags = self.ksspi.get_ticket_for_spn(self.spn, ctx_flags = self.flags)
				self.iterations += 1
				

				if ISC_REQ.MUTUAL_AUTH in self.actual_ctx_flags or ISC_REQ.USE_DCE_STYLE in self.actual_ctx_flags:
					#in these cases continuation is needed
					return token, True, None
				
				else:
					#no mutual or dce auth will take one step only
					_, err = self.get_session_key()
					if err is not None:
						return None, None, err
					apreq = AP_REQ.load(token).native
					subkey = Key(apreq['ticket']['enc-part']['etype'], self.session_key)
					self.gssapi = get_gssapi(subkey)
					self.get_seq_number()
						
					return token, False, None

			
			else:
				adata = authData[16:]
				if ISC_REQ.USE_DCE_STYLE in self.actual_ctx_flags:
					adata = authData
				token, self.actual_ctx_flags = self.ksspi.get_ticket_for_spn(self.spn, ctx_flags = self.actual_ctx_flags, token_data = adata)
				
				

				if ISC_REQ.USE_DCE_STYLE in self.actual_ctx_flags:
					#Using DCE style 3-legged auth
					aprep = AP_REP.load(token).native
				else:
					aprep = AP_REP.load(adata).native
					subkey = Key(aprep['enc-part']['etype'], self.get_session_key())

				_, err = self.get_session_key()
				if err is not None:
					return None, None, err
				
				_, err = self.get_seq_number()
				if err is not None:
					return None, None, err

				subkey = Key(token['enc-part']['etype'], self.session_key)
				self.gssapi = get_gssapi(subkey)
				
				self.iterations += 1
				return token, False, None
			
		except Exception as e:
			return None, None, e
		