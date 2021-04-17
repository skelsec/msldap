#
#
# This is just a simple interface to the minikerberos library to support SPNEGO
# 
#
# - Links - 
# 1. See minikerberos library

import datetime

import os
from minikerberos.common import *


from minikerberos.protocol.asn1_structs import AP_REP, EncAPRepPart, EncryptedData, AP_REQ, Ticket
from msldap.authentication.kerberos.gssapi import get_gssapi, KRB5_MECH_INDEP_TOKEN
from msldap.commons.proxy import MSLDAPProxyType
from minikerberos.protocol.structures import ChecksumFlags
from minikerberos.protocol.encryption import Enctype, Key, _enctype_table
from minikerberos.protocol.constants import MESSAGE_TYPE
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.network.aioclientsockssocket import AIOKerberosClientSocksSocket
from msldap import logger

# SMBKerberosCredential

MSLDAP_SOCKS_PROXY_TYPES = [
	MSLDAPProxyType.SOCKS4, 
	MSLDAPProxyType.SOCKS4_SSL, 
	MSLDAPProxyType.SOCKS5, 
	MSLDAPProxyType.SOCKS5_SSL,
	MSLDAPProxyType.WSNET,
]

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
		self.preferred_etypes = [23,17,18]
		
		self.session_key = None
		self.gssapi = None
		self.iterations = 0
		self.etype = None
		self.seq_number = 0
		self.expected_server_seq_number = None
		self.from_ccache = False
	
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
		if self.settings.enctypes is not None:
			self.preferred_etypes = self.settings.enctypes
		
		self.flags = ChecksumFlags.GSS_C_MUTUAL_FLAG
		if self.settings.encrypt is True:
			self.flags = \
				ChecksumFlags.GSS_C_CONF_FLAG |\
				ChecksumFlags.GSS_C_INTEG_FLAG |\
				ChecksumFlags.GSS_C_REPLAY_FLAG |\
				ChecksumFlags.GSS_C_SEQUENCE_FLAG
		
	
	def get_session_key(self):
		return self.session_key.contents, None


	async def setup_kc(self):
		try:
			# sockst/wsnet proxying is handled by the minikerberos&asysocks modules
			if self.target.proxy is None or self.target.proxy.type in MSLDAP_SOCKS_PROXY_TYPES:
				self.kc = AIOKerberosClient(self.ccred, self.target)

			elif self.target.proxy.type in [MSLDAPProxyType.MULTIPLEXOR, MSLDAPProxyType.MULTIPLEXOR_SSL]:
				from msldap.network.multiplexor import MultiplexorProxyConnection
				mpc = MultiplexorProxyConnection(self.target)
				socks_proxy = await mpc.connect(is_kerberos = True)

				self.kc = AIOKerberosClient(self.ccred, socks_proxy)

			else:
				raise Exception('Unknown proxy type %s' % self.target.proxy.type)

			return None, None
		except Exception as e:
			return None, e
	
	async def authenticate(self, authData, flags = None, seq_number = 0, cb_data = None):
		"""
		This function is called (multiple times depending on the flags) to perform authentication. 
		"""
		try:
			if self.kc is None:
				_, err = await self.setup_kc()
				if err is not None:
					return None, None, err

			if self.iterations == 0:
				self.seq_number = 0
				self.iterations += 1
				
				try:
					#check TGS first, maybe ccache already has what we need
					for target in self.ccred.ccache.list_targets():
						# just printing this to debug...
						logger.debug('CCACHE SPN record: %s' % target)
					tgs, encpart, self.session_key = await self.kc.get_TGS(self.spn)
					
					self.from_ccache = True
				except:
					tgt = await self.kc.get_TGT(override_etype = self.preferred_etypes)
					tgs, encpart, self.session_key = await self.kc.get_TGS(self.spn)#, override_etype = self.preferred_etypes)

				#self.expected_server_seq_number = encpart.get('nonce', seq_number)
				
				ap_opts = []
				if ChecksumFlags.GSS_C_MUTUAL_FLAG in self.flags or ChecksumFlags.GSS_C_DCE_STYLE in self.flags:
					if ChecksumFlags.GSS_C_MUTUAL_FLAG in self.flags:
						ap_opts.append('mutual-required')
					if self.from_ccache is False:
						apreq = self.kc.construct_apreq(tgs, encpart, self.session_key, flags = self.flags, seq_number = self.seq_number, ap_opts=ap_opts, cb_data = cb_data)
					else:
						apreq = self.kc.construct_apreq_from_ticket(Ticket(tgs['ticket']).dump(), self.session_key, tgs['crealm'], tgs['cname']['name-string'][0], flags = self.flags, seq_number = self.seq_number, ap_opts = ap_opts, cb_data = cb_data)
					return apreq, True, None
				
				else:
					#no mutual or dce auth will take one step only
					if self.from_ccache is False:
						apreq = self.kc.construct_apreq(tgs, encpart, self.session_key, flags = self.flags, seq_number = self.seq_number, ap_opts=[], cb_data = cb_data)
					else:
						apreq = self.kc.construct_apreq_from_ticket(Ticket(tgs['ticket']).dump(), self.session_key, tgs['crealm'], tgs['cname']['name-string'][0], flags = self.flags, seq_number = self.seq_number, ap_opts = ap_opts, cb_data = cb_data)
					
					
					self.gssapi = get_gssapi(self.session_key)
					return apreq, False, None

			else:
				self.iterations += 1
				if ChecksumFlags.GSS_C_DCE_STYLE in self.flags:
					# adata = authData[16:]
					# if ChecksumFlags.GSS_C_DCE_STYLE in self.flags:
					#	adata = authData
					raise Exception('DCE auth Not implemented!')
				
				# at this point we are dealing with mutual authentication
				# This means that the server sent back an AP-rep wrapped in a token
				# The APREP contains a new session key we'd need to update and a seq-number 
				# that is expected the server will use for future communication.
				# For mutual auth we dont need to reply anything after this step, 
				# but for DCE auth a reply is expected. TODO

				# converting the token to aprep
				token = KRB5_MECH_INDEP_TOKEN.from_bytes(authData)
				if token.data[:2] != b'\x02\x00':
					raise Exception('Unexpected token type! %s' % token.data[:2].hex() )
				aprep = AP_REP.load(token.data[2:]).native
				
				# decrypting aprep
				cipher = _enctype_table[int(aprep['enc-part']['etype'])]()
				cipher_text = aprep['enc-part']['cipher']
				temp = cipher.decrypt(self.session_key, 12, cipher_text)
				enc_part = EncAPRepPart.load(temp).native

				#updating session key, gssapi
				self.session_key = Key(int(enc_part['subkey']['keytype']), enc_part['subkey']['keyvalue'])
				#self.seq_number = enc_part.get('seq-number', 0)
				self.gssapi = get_gssapi(self.session_key)

				return b'', False, None		
		
		except Exception as e:
			return None, None, e