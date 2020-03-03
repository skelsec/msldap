import enum
import platform

import copy
from msldap.commons.credential import MSLDAPCredential, LDAPAuthProtocol
from msldap.authentication.spnego.native import SPNEGO
from msldap.authentication.ntlm.native import NTLMAUTHHandler, NTLMHandlerSettings
from msldap.authentication.kerberos.native import SMBKerberos
from minikerberos.common.target import KerberosTarget
from minikerberos.common.proxy import KerberosProxy
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.spn import KerberosSPN

from minikerberos.network.selector import KerberosClientSocketSelector


if platform.system().upper() == 'WINDOWS':
	from aiosmb.authentication.kerberos.sspi import SMBKerberosSSPI
	from aiosmb.authentication.ntlm.sspi import SMBNTLMSSPI

class MSLDAPNTLMCredential:
	def __init__(self):
		self.username = None
		self.domain = ''
		self.password = None
		self.workstation = None
		self.is_guest = False
		self.nt_hash = None
		self.lm_hash = None

class AuthenticatorBuilder:
	def __init__(self, creds, target = None):
		self.creds = creds
		self.target = target
	
	def build(self):
		if self.creds.auth_method == LDAPAuthProtocol.NTLM:
			ntlmcred = MSLDAPNTLMCredential()
			ntlmcred.username = self.creds.username
			ntlmcred.domain = self.creds.domain if self.creds.domain is not None else ''
			ntlmcred.workstation = None
			ntlmcred.is_guest = False
			
			if self.creds.password is None:
				raise Exception('NTLM authentication requres password!')
			ntlmcred.password = self.creds.password
			
			settings = NTLMHandlerSettings(ntlmcred)
			return NTLMAUTHHandler(settings)
			
			##setting up SPNEGO
			#spneg = SPNEGO()
			#spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
			
			#return spneg

		if self.creds.auth_method == LDAPAuthProtocol.GSSAPI:
			ntlmcred = MSLDAPNTLMCredential()
			ntlmcred.username = self.creds.username
			ntlmcred.domain = self.creds.domain if self.creds.domain is not None else ''
			ntlmcred.workstation = None
			ntlmcred.is_guest = False
			
			if self.creds.password is None:
				raise Exception('NTLM authentication requres password!')
			ntlmcred.password = self.creds.password
			
			settings = NTLMHandlerSettings(ntlmcred)
			handler = NTLMAUTHHandler(settings)
			
			##setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
			
			return spneg




	@staticmethod
	def to_spnego_cred(creds, target = None):
		pass