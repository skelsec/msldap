#
#
# This is just a simple interface to the minikerberos library to support SPNEGO
# 
#
# - Hardships - 
# 1. DCERPC kerberos authentication requires a complete different approach and flags,
#    also requires mutual authentication
#
# - Links - 
# 1. Most of the idea was taken from impacket
# 2. See minikerberos library

import datetime

from minikerberos.common import *

from minikerberos.protocol.asn1_structs import AP_REP, EncAPRepPart, EncryptedData, AP_REQ
from msldap.authentication.kerberos.gssapi import get_gssapi
from minikerberos.protocol.structures import ChecksumFlags
from minikerberos.protocol.encryption import Enctype, Key, _enctype_table
from minikerberos.protocol.constants import MESSAGE_TYPE
from minikerberos.aioclient import AIOKerberosClient

# SMBKerberosCredential

class MSLDAPKerberos:
	def __init__(self, settings):
		self.settings = settings
		self.signing_preferred = None
		self.encryption_preferred = None
		self.ccred = None
		self.target = None
		self.spn = None
		self.kc = None
		self.flags = None
		self.preferred_etypes = [23]
		
		self.session_key = None
		self.gssapi = None
		self.iterations = 0
		self.etype = None
		self.seq_number = 0
		self.expected_server_seq_number = None
	
		self.setup()
	
	def get_seq_number(self):
		"""
		Returns the initial sequence number. It is 0 by default, but can be adjusted during authentication, 
		by passing the 'seq_number' parameter in the 'authenticate' function
		"""
		return self.seq_number
	
	def signing_needed(self):
		"""
		Checks if integrity protection was negotiated
		"""
		return ChecksumFlags.GSS_C_INTEG_FLAG in self.flags
	
	def encryption_needed(self):
		"""
		Checks if confidentiality flag was negotiated
		"""
		return ChecksumFlags.GSS_C_CONF_FLAG in self.flags
				
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
		
	def setup(self):
		self.ccred = self.settings.ccred
		self.spn = self.settings.spn
		self.target = self.settings.target
		self.channelbind = self.settings.channelbind
		
		self.flags = ChecksumFlags.GSS_C_MUTUAL_FLAG
		if self.channelbind is True:
			self.flags = \
				ChecksumFlags.GSS_C_INTEG_FLAG |\
				ChecksumFlags.GSS_C_CONF_FLAG |\
				ChecksumFlags.GSS_C_REPLAY_FLAG |\
				ChecksumFlags.GSS_C_SEQUENCE_FLAG #|\
				#ChecksumFlags.GSS_C_MUTUAL_FLAG #DONT ENABLE THIS it's not implemented here :( TODO !!!!!!!!

		self.kc = AIOKerberosClient(self.ccred, self.target)
	
	def get_session_key(self):
		return self.session_key.contents, None
	
	async def authenticate(self, authData, flags = None, seq_number = 0, is_rpc = False):
		"""
		This function is called (multiple times depending on the flags) to perform authentication. 
		"""
		print(self.iterations)
		try:
			print(self.flags)
			
			if self.iterations == 0:
				self.seq_number = seq_number
				self.iterations += 1

				#tgt = await self.kc.get_TGT()
				tgt = await self.kc.get_TGT(override_etype = self.preferred_etypes)
				tgs, encpart, self.session_key = await self.kc.get_TGS(self.spn, override_etype = self.preferred_etypes)
				
				print(encpart)
				self.expected_server_seq_number = encpart.get('nonce', seq_number)
				
				ap_opts = []
				if ChecksumFlags.GSS_C_MUTUAL_FLAG in self.flags or ChecksumFlags.GSS_C_DCE_STYLE in self.flags:
					if ChecksumFlags.GSS_C_MUTUAL_FLAG in self.flags:
						ap_opts.append('mutual-required')
					apreq = self.kc.construct_apreq(tgs, encpart, self.session_key, flags = self.flags, seq_number = self.seq_number, ap_opts=ap_opts)
					return apreq, True, None
				
				else:
					#no mutual or dce auth will take one step only
					apreq = self.kc.construct_apreq(tgs, encpart, self.session_key, flags = self.flags, seq_number = self.seq_number, ap_opts=[])
					self.gssapi = get_gssapi(self.session_key)
					return apreq, False, None

			else:
				raise Exception('Not implemented!')
				adata = authData[16:]
				if ChecksumFlags.GSS_C_DCE_STYLE in self.flags:
					adata = authData

				apreq = self.kc.construct_apreq(tgs, encpart, self.session_key, flags = self.flags, seq_number = seq_number, ap_opts=ap_opts)
				
				

				if ChecksumFlags.GSS_C_DCE_STYLE in self.flags:
					#Using DCE style 3-legged auth
					aprep = AP_REP.load(token).native
				else:
					aprep = AP_REP.load(adata).native
					subkey = Key(aprep['enc-part']['etype'], self.get_session_key())

				subkey = Key(token['enc-part']['etype'], self.session_key)
				self.gssapi = get_gssapi(subkey)
				
				self.iterations += 1
				return token, False, None
			
		
		except Exception as e:
			return None, None, e