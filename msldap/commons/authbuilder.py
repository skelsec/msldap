import enum
import platform

import copy
from msldap.commons.credential import MSLDAPCredential, LDAPAuthProtocol
from msldap.authentication.spnego.native import SPNEGO
from msldap.authentication.ntlm.native import NTLMAUTHHandler, NTLMHandlerSettings
from msldap.authentication.kerberos.native import MSLDAPKerberos
from msldap.commons.proxy import MSLDAPProxyType
from minikerberos.common.target import KerberosTarget
from minikerberos.common.proxy import KerberosProxy
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.spn import KerberosSPN

from minikerberos.network.selector import KerberosClientSocketSelector


if platform.system().upper() == 'WINDOWS':
	from msldap.authentication.kerberos.sspi import MSLDAPKerberosSSPI
	from msldap.authentication.ntlm.sspi import MSLDAPNTLMSSPI

class MSLDAPNTLMCredential:
	def __init__(self):
		self.username = None
		self.domain = ''
		self.password = None
		self.workstation = None
		self.is_guest = False
		self.nt_hash = None
		self.lm_hash = None 
		self.encrypt = False

class MSLDAPSIMPLECredential:
	def __init__(self):
		self.username = None
		self.domain = None
		self.password = None

class MSLDAPPLAINCredential:
	def __init__(self):
		self.username = None
		self.domain = None
		self.password = None

class MSLDAPKerberosCredential:
	def __init__(self):
		self.connection = None #KerberosCredential
		self.target = None #KerberosTarget
		self.ksoc = None #KerberosSocketAIO
		self.ccred = None
		self.encrypt = False
		self.enctypes = None #[23,17,18]

class MSLDAPKerberosSSPICredential:
	def __init__(self):
		self.domain = None
		self.password = None
		self.username  = None
		self.encrypt = False
		
class MSLDAPNTLMSSPICredential:
	def __init__(self):
		self.username = None
		self.password = None
		self.domain = None
		self.encrypt = False

class MSLDAPWSNETCredential:
	def __init__(self):
		self.type = 'NTLM'
		self.username = '<CURRENT>'
		self.domain = '<CURRENT>'
		self.password = '<CURRENT>'
		self.target = None
		self.is_guest = False
		self.agent_id = None
		self.encrypt = False

class MSLDAPSSPIProxyCredential:
	def __init__(self):
		self.type = 'NTLM'
		self.username = '<CURRENT>'
		self.domain = '<CURRENT>'
		self.password = '<CURRENT>'
		self.target = None
		self.is_guest = False
		self.agent_id = None
		self.encrypt = False
		self.host = '127.0.0.1'
		self.port = 9999
		self.proto = 'ws'

		

class MSLDAPMultiplexorCredential:
	def __init__(self):
		self.type = 'NTLM'
		self.username = '<CURRENT>'
		self.domain = '<CURRENT>'
		self.password = '<CURRENT>'
		self.target = None
		self.is_guest = False
		self.is_ssl = False
		self.mp_host = '127.0.0.1'
		self.mp_port = 9999
		self.mp_username = None
		self.mp_domain = None
		self.mp_password = None
		self.agent_id = None
		self.encrypt = False

	def get_url(self):
		url_temp = 'ws://%s:%s'
		if self.is_ssl is True:
			url_temp = 'wss://%s:%s'
		url = url_temp % (self.mp_host, self.mp_port)
		return url

	def parse_settings(self, settings):
		req = ['agentid']
		for r in req:
			if r not in settings:
				raise Exception('%s parameter missing' % r)
		self.mp_host = settings.get('host', ['127.0.0.1'])[0]
		self.mp_port = settings.get('port', ['9999'])[0]
		if self.mp_port is None:
			self.mp_port = '9999'
		if 'user' in settings:
			self.mp_username = settings.get('user')[0]
		if 'domain' in settings:
			self.mp_domain = settings.get('domain')[0]
		if 'password' in settings:
			self.mp_password = settings.get('password')[0]
		self.agent_id = settings['agentid'][0]



"""
class LDAPAuthProtocol(enum.Enum):
	PLAIN = 'PLAIN' #actually SASL-PLAIN

	MULTIPLEXOR = 'MULTIPLEXOR'
	MULTIPLEXOR_SSL = 'MULTIPLEXOR_SSL'
	SSPI_NTLM = 'SSPI_NTLM' #actually SASL-GSSAPI-SPNEGO-NTLM but with integrated SSPI
	SSPI_KERBEROS = 'SSPI_KERBEROS' #actually SASL-GSSAPI-SPNEGO-KERBEROS but with integrated SSPI
"""

class AuthenticatorBuilder:
	def __init__(self, creds, target = None):
		self.creds = creds
		self.target = target
	
	def build(self):
		if self.creds.auth_method == LDAPAuthProtocol.SICILY:
			ntlmcred = MSLDAPNTLMCredential()
			ntlmcred.username = self.creds.username
			ntlmcred.domain = self.creds.domain if self.creds.domain is not None else ''
			ntlmcred.workstation = None
			ntlmcred.is_guest = False
			ntlmcred.encrypt = self.creds.encrypt

			
			if self.creds.password is None:
				raise Exception('NTLM authentication requres password/NT hash!')
			
			
			if len(self.creds.password) == 32:
				try:
					bytes.fromhex(self.creds.password)
				except:
					ntlmcred.password = self.creds.password
				else:
					ntlmcred.nt_hash = self.creds.password
			
			else:
				ntlmcred.password = self.creds.password
			
			settings = NTLMHandlerSettings(ntlmcred)
			return NTLMAUTHHandler(settings)

		elif self.creds.auth_method == LDAPAuthProtocol.SIMPLE:
			cred = MSLDAPPLAINCredential()
			cred.username = self.creds.username
			cred.domain = self.creds.domain
			cred.password = self.creds.password
			return cred

		elif self.creds.auth_method == LDAPAuthProtocol.PLAIN:
			cred = MSLDAPSIMPLECredential()
			cred.username = self.creds.username
			cred.domain = self.creds.domain
			cred.password = self.creds.password
			return cred

		elif self.creds.auth_method in [LDAPAuthProtocol.NTLM_PASSWORD, LDAPAuthProtocol.NTLM_NT]:
			ntlmcred = MSLDAPNTLMCredential()
			ntlmcred.username = self.creds.username
			ntlmcred.domain = self.creds.domain if self.creds.domain is not None else ''
			ntlmcred.workstation = None
			ntlmcred.is_guest = False
			ntlmcred.encrypt = self.creds.encrypt
			
			if self.creds.password is None:
				raise Exception('NTLM authentication requres password!')

			if self.creds.auth_method == LDAPAuthProtocol.NTLM_PASSWORD:
				ntlmcred.password = self.creds.password
			elif self.creds.auth_method == LDAPAuthProtocol.NTLM_NT:
				ntlmcred.nt_hash = self.creds.password
			else:
				raise Exception('Unknown NTLM auth method!')
			
			settings = NTLMHandlerSettings(ntlmcred)
			handler = NTLMAUTHHandler(settings)
			
			##setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
			
			return spneg

		elif self.creds.auth_method in [
				LDAPAuthProtocol.KERBEROS_RC4, 
				LDAPAuthProtocol.KERBEROS_NT, 
				LDAPAuthProtocol.KERBEROS_AES,
				LDAPAuthProtocol.KERBEROS_PASSWORD, 
				LDAPAuthProtocol.KERBEROS_CCACHE, 
				LDAPAuthProtocol.KERBEROS_KEYTAB,
				LDAPAuthProtocol.KERBEROS_KIRBI]:
			
			if self.target is None:
				raise Exception('Target must be specified with Kerberos!')
				
			if self.target.host is None:
				raise Exception('target must have a domain name or hostname for kerberos!')
				
			if self.target.dc_ip is None:
				raise Exception('target must have a dc_ip for kerberos!')
			
			kcred = MSLDAPKerberosCredential()
			if self.creds.auth_method == LDAPAuthProtocol.KERBEROS_KIRBI:
				kc = KerberosCredential.from_kirbi(self.creds.password, self.creds.username, self.creds.domain)
			elif self.creds.auth_method == LDAPAuthProtocol.KERBEROS_CCACHE:
				kc = KerberosCredential.from_ccache_file(self.creds.password, self.creds.username, self.creds.domain)
			elif self.creds.auth_method == LDAPAuthProtocol.KERBEROS_KEYTAB:
				kc = KerberosCredential.from_kirbi(self.creds.password, self.creds.username, self.creds.domain)
			else:
				kc = KerberosCredential()
				kc.username = self.creds.username
				kc.domain = self.creds.domain
			kcred.enctypes = []
			if self.creds.auth_method == LDAPAuthProtocol.KERBEROS_PASSWORD:
				kc.password = self.creds.password
				kcred.enctypes = [23,17,18]
			elif self.creds.auth_method == LDAPAuthProtocol.KERBEROS_NT:
				kc.nt_hash = self.creds.password
				kcred.enctypes = [23]
				
			elif self.creds.auth_method == LDAPAuthProtocol.KERBEROS_AES:
				if len(self.creds.password) == 32:
					kc.kerberos_key_aes_128 = self.creds.password
					kcred.enctypes = [17]
				elif len(self.creds.password) == 64:
					kc.kerberos_key_aes_256 = self.creds.password
					kcred.enctypes = [18]
					
			elif self.creds.auth_method == LDAPAuthProtocol.KERBEROS_RC4:
				kc.kerberos_key_rc4 = self.creds.password
				kcred.enctypes = [23]
			
			elif self.creds.auth_method == LDAPAuthProtocol.KERBEROS_CCACHE:
				kc.ccache = self.creds.password
				kcred.enctypes = [23,17,18] # TODO: fix this
			elif self.creds.auth_method == LDAPAuthProtocol.KERBEROS_KEYTAB:
				kc.keytab = self.creds.password
				kcred.enctypes = [23,17,18] # TODO: fix this
			elif self.creds.auth_method == LDAPAuthProtocol.KERBEROS_KIRBI:
				kcred.enctypes = [23,17,18] # TODO: fix this
			else:
				raise Exception('No suitable secret type found to set up kerberos!')

			if self.creds.etypes is not None:
				kcred.enctypes = list(set(self.creds.etypes).intersection(set(kcred.enctypes)))				
			
			kcred.ccred = kc
			kcred.spn = KerberosSPN.from_target_string(self.target.to_target_string())
			kcred.target = KerberosTarget(self.target.dc_ip)
			kcred.encrypt = self.creds.encrypt
			
			if self.target.proxy is not None:
					kcred.target.proxy = KerberosProxy()
					kcred.target.proxy.type = self.target.proxy.type
					kcred.target.proxy.target = copy.deepcopy(self.target.proxy.target)
					kcred.target.proxy.target[-1].endpoint_ip = self.target.dc_ip
					kcred.target.proxy.target[-1].endpoint_port = 88

			handler = MSLDAPKerberos(kcred)
			
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
			return spneg

		elif self.creds.auth_method == LDAPAuthProtocol.SSPI_KERBEROS:
			if self.target is None:
				raise Exception('Target must be specified with Kerberos SSPI!')
				
			kerbcred = MSLDAPKerberosSSPICredential()
			kerbcred.username = self.creds.domain if self.creds.domain is not None else '<CURRENT>'
			kerbcred.username = self.creds.username if self.creds.username is not None else '<CURRENT>'
			kerbcred.password = self.creds.password if self.creds.password is not None else '<CURRENT>'
			kerbcred.spn = self.target.to_target_string()
			kerbcred.encrypt = self.creds.encrypt
			
			handler = MSLDAPKerberosSSPI(kerbcred)
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
			return spneg
		
		elif self.creds.auth_method == LDAPAuthProtocol.SSPI_NTLM:
			ntlmcred = MSLDAPNTLMSSPICredential()
			ntlmcred.username = self.creds.domain if self.creds.domain is not None else '<CURRENT>'
			ntlmcred.username = self.creds.username if self.creds.username is not None else '<CURRENT>'
			ntlmcred.password = self.creds.password if self.creds.password is not None else '<CURRENT>'
			ntlmcred.encrypt = self.creds.encrypt

			handler = MSLDAPNTLMSSPI(ntlmcred)
			#setting up SPNEGO
			spneg = SPNEGO()
			spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
			return spneg

		elif self.creds.auth_method.value.startswith('MULTIPLEXOR'):
			if self.creds.auth_method in [LDAPAuthProtocol.MULTIPLEXOR_SSL_NTLM, LDAPAuthProtocol.MULTIPLEXOR_NTLM]:
				from msldap.authentication.ntlm.multiplexor import MSLDAPNTLMMultiplexor
				ntlmcred = MSLDAPMultiplexorCredential()
				ntlmcred.type = 'NTLM'
				if self.creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if self.creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if self.creds.password is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False
				ntlmcred.is_ssl = True if self.creds.auth_method == LDAPAuthProtocol.MULTIPLEXOR_SSL_NTLM else False
				ntlmcred.parse_settings(self.creds.settings)
				ntlmcred.encrypt = self.creds.encrypt
				
				handler = MSLDAPNTLMMultiplexor(ntlmcred)
				#setting up SPNEGO
				spneg = SPNEGO()
				spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
				return spneg

			elif self.creds.auth_method in [LDAPAuthProtocol.MULTIPLEXOR_SSL_KERBEROS, LDAPAuthProtocol.MULTIPLEXOR_KERBEROS]:
				from msldap.authentication.kerberos.multiplexor import MSLDAPKerberosMultiplexor

				ntlmcred = MSLDAPMultiplexorCredential()
				ntlmcred.type = 'KERBEROS'
				ntlmcred.target = self.target
				if self.creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if self.creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if self.creds.password is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False
				ntlmcred.is_ssl = True if self.creds.auth_method == LDAPAuthProtocol.MULTIPLEXOR_SSL_NTLM else False
				ntlmcred.parse_settings(self.creds.settings)
				ntlmcred.encrypt = self.creds.encrypt

				handler = MSLDAPKerberosMultiplexor(ntlmcred)
				#setting up SPNEGO
				spneg = SPNEGO()
				spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
				return spneg

		elif self.creds.auth_method.value.startswith('SSPIPROXY'):
			if self.creds.auth_method == LDAPAuthProtocol.SSPIPROXY_NTLM:
				from msldap.authentication.ntlm.sspiproxy import MSLDAPSSPIProxyNTLMAuth
				ntlmcred = MSLDAPSSPIProxyCredential()
				ntlmcred.type = 'NTLM'
				if self.creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if self.creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if self.creds.password is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False
				ntlmcred.encrypt = self.creds.encrypt
				ntlmcred.host = self.creds.settings['host'][0]
				ntlmcred.port = int(self.creds.settings['port'][0])
				ntlmcred.proto = 'ws'
				if 'proto' in self.creds.settings:
					ntlmcred.proto = self.creds.settings['proto'][0]
				if 'agentid' in self.creds.settings:
					ntlmcred.agent_id = bytes.fromhex(self.creds.settings['agentid'][0])
				
				handler = MSLDAPSSPIProxyNTLMAuth(ntlmcred)
				#setting up SPNEGO
				spneg = SPNEGO()
				spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
				return spneg

			elif self.creds.auth_method == LDAPAuthProtocol.SSPIPROXY_KERBEROS:
				from msldap.authentication.kerberos.sspiproxyws import MSLDAPSSPIProxyKerberosAuth

				ntlmcred = MSLDAPSSPIProxyCredential()
				ntlmcred.type = 'KERBEROS'
				ntlmcred.target = self.target
				if self.creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if self.creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if self.creds.password is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False
				ntlmcred.encrypt = self.creds.encrypt
				ntlmcred.host = self.creds.settings['host'][0]
				ntlmcred.port = self.creds.settings['port'][0]
				ntlmcred.proto = 'ws'
				if 'proto' in self.creds.settings:
					ntlmcred.proto = self.creds.settings['proto'][0]
				if 'agentid' in self.creds.settings:
					ntlmcred.agent_id = bytes.fromhex(self.creds.settings['agentid'][0])

				handler = MSLDAPSSPIProxyKerberosAuth(ntlmcred)
				#setting up SPNEGO
				spneg = SPNEGO()
				spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
				return spneg

		elif self.creds.auth_method.value.startswith('WSNET'):
			if self.creds.auth_method in [LDAPAuthProtocol.WSNET_NTLM]:
				from msldap.authentication.ntlm.wsnet import MSLDAPWSNetNTLMAuth
				
				ntlmcred = MSLDAPWSNETCredential()
				ntlmcred.type = 'NTLM'
				if self.creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if self.creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if self.creds.password is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False
				
				handler = MSLDAPWSNetNTLMAuth(ntlmcred)
				spneg = SPNEGO()
				spneg.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', handler)
				return spneg
			

			elif self.creds.auth_method in [LDAPAuthProtocol.WSNET_KERBEROS]:
				from msldap.authentication.kerberos.wsnet import MSLDAPWSNetKerberosAuth

				ntlmcred = MSLDAPWSNETCredential()
				ntlmcred.type = 'KERBEROS'
				ntlmcred.target = self.target
				if self.creds.username is not None:
					ntlmcred.username = '<CURRENT>'
				if self.creds.domain is not None:
					ntlmcred.domain = '<CURRENT>'
				if self.creds.password is not None:
					ntlmcred.password = '<CURRENT>'
				ntlmcred.is_guest = False

				handler = MSLDAPWSNetKerberosAuth(ntlmcred)
				#setting up SPNEGO
				spneg = SPNEGO()
				spneg.add_auth_context('MS KRB5 - Microsoft Kerberos 5', handler)
				return spneg