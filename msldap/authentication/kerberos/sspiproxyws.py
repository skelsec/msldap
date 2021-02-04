
## 
##
## Interface to allow remote kerberos authentication via Multiplexor
## 
##
##
##
##
## TODO: RPC auth type is not implemented or tested!!!!

import enum

from msldap.authentication.spnego.asn1_structs import KRB5Token
from msldap.authentication.kerberos.gssapi import get_gssapi, GSSWrapToken, KRB5_MECH_INDEP_TOKEN
from minikerberos.protocol.asn1_structs import AP_REQ, AP_REP, TGS_REP
from minikerberos.protocol.encryption import Enctype, Key, _enctype_table
from pyodidewsnet.sspiproxyws import SSPIProxyWS


# mutual auth not supported
# encryption is always on

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

class MSLDAPSSPIProxyKerberosAuth:
	def __init__(self, settings):
		self.iterations = 0
		self.settings = settings
		self.mode = 'CLIENT'
		url = '%s://%s:%s' % (self.settings.proto, self.settings.host, self.settings.port)
		self.sspi = SSPIProxyWS(url, self.settings.agent_id)
		self.client = None
		self.target = None
		self.gssapi = None
		self.etype = None
		self.session_key = None
		self.seq_number = 0
		self.flags = ISC_REQ.CONNECTION
		
		self.setup()
		
	def setup(self):
		if self.settings.encrypt is True:
			self.flags = \
				ISC_REQ.CONFIDENTIALITY |\
				ISC_REQ.INTEGRITY |\
				ISC_REQ.REPLAY_DETECT |\
				ISC_REQ.SEQUENCE_DETECT

	def get_seq_number(self):
		return self.seq_number
		
	async def encrypt(self, data, message_no):
		return self.gssapi.GSS_Wrap(data, message_no)
		
	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		return self.gssapi.GSS_Unwrap(data, message_no, direction=direction, auth_data=auth_data)
	
	def signing_needed(self):
		"""
		Checks if integrity protection was negotiated
		"""
		return ISC_REQ.INTEGRITY in self.flags

	def encryption_needed(self):
		"""
		Checks if confidentiality flag was negotiated
		"""
		return ISC_REQ.CONFIDENTIALITY in self.flags

	def get_session_key(self):
		return self.session_key
	
	async def authenticate(self, authData = None, flags = None, seq_number = 0, cb_data=None):
		try:
			status, ctxattr, apreq, err = await self.sspi.authenticate('KERBEROS', '', self.settings.target.to_target_string(), 3, self.flags.value, authdata = b'')
			if err is not None:
				raise err
			
			self.flags = ISC_REQ(ctxattr)

			self.session_key, err = await self.sspi.get_sessionkey()
			if err is not None:
				return None, None, err

			unwrap = KRB5_MECH_INDEP_TOKEN.from_bytes(apreq)
			aprep = AP_REQ.load(unwrap.data[2:]).native
			subkey = Key(aprep['ticket']['enc-part']['etype'], self.session_key)
			self.gssapi = get_gssapi(subkey)
				
			if aprep['ticket']['enc-part']['etype'] != 23:
				if ISC_REQ.CONFIDENTIALITY in self.flags:
					raw_seq_data, err = await self.sspi.get_sequenceno()
					if err is not None:
						return None, None, err
					self.seq_number = GSSWrapToken.from_bytes(raw_seq_data[16:]).SND_SEQ
				
			return unwrap.data[2:], False, None
		except Exception as e:
			return None, None, e

		