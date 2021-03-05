
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import platform
import hashlib
import getpass
import base64
import enum
from urllib.parse import urlparse, parse_qs

from msldap.commons.credential import MSLDAPCredential, LDAPAuthProtocol, MSLDAP_KERBEROS_PROTOCOLS
from msldap.commons.target import MSLDAPTarget, LDAPProtocol
from msldap.commons.proxy import MSLDAPProxy, MSLDAPProxyType
from msldap.client import MSLDAPClient
from msldap.connection import MSLDAPClientConnection

class PLAINTEXTSCHEME(enum.Enum):
	"""
	Additional conveinence functions.
	"""
	SIMPLE_PROMPT = 'SIMPLE_PROMPT'
	SIMPLE_HEX = 'SIMPLE_HEX'
	SIMPLE_B64 = 'SIMPLE_B64'
	PLAIN_PROMPT = 'PLAIN_PROMPT'
	PLAIN_HEX = 'PLAIN_HEX'
	PLAIN_B64 = 'PLAIN_B64'
	SICILY_PROMPT = 'SICILY_PROMPT'
	SICILY_HEX = 'SICILY_HEX'
	SICILY_B64 = 'SICILY_B64'
	NTLM_PROMPT = 'NTLM_PROMPT'
	NTLM_HEX = 'NTLM_HEX'
	NTLM_B64 = 'NTLM_B64'

class MSLDAPURLDecoder:
	"""
	The URL describes both the connection target and the credentials. This class creates all necessary objects to set up the client.
	
	:param url: 
	:type url: str
	"""

	help_epilog = """
	MSLDAP URL Format: <protocol>+<auth>://<username>:<password>@<ip_or_host>:<port>/<tree>/?<param>=<value>
	<protocol> sets the ldap protocol following values supported:
		- ldap
		- ldaps
	<auth> can be omitted if plaintext authentication is to be performed (in that case it default to ntlm-password), otherwise:
		- ntlm-password
		- ntlm-nt
		- kerberos-password (dc option param must be used)
		- kerberos-rc4 / kerberos-nt (dc option param must be used)
		- kerberos-aes (dc option param must be used)
		- kerberos-keytab (dc option param must be used)
		- kerberos-ccache (dc option param must be used)
		- sspi-ntlm (windows only!)
		- sspi-kerberos (windows only!)
		- anonymous
		- plain
		- simple
		- sicily (same format as ntlm-nt but using the SICILY authentication)
	<tree>:
		OPTIONAL. Specifies the root tree of all queries
	<param> can be:
		- timeout : connction timeout in seconds
		- proxytype: currently only socks5 proxy is supported
		- proxyhost: Ip or hostname of the proxy server
		- proxyport: port of the proxy server
		- proxytimeout: timeout in secodns for the proxy connection
		- dc: the IP address of the domain controller, MUST be used for kerberos authentication
		- encrypt: enable encryption. Only for NTLM. DOESNT WORK WITH LDAPS
		- etype: Supported encryption types for Kerberos authentication. Multiple can be specified.
		- rate: LDAP paged search query rate limit. Will sleep for seconds between each new page. Default: 0 (no limit)
		- pagesize: LDAP paged search query size per page. Max: 1000. Default: 1000

	Examples:
	ldap://10.10.10.2 (anonymous bind)
	ldaps://test.corp (anonymous bind)
	ldap+sspi-ntlm://test.corp
	ldap+sspi-kerberos://test.corp
	ldap://TEST\\victim:<password>@10.10.10.2 (defaults to SASL GSSAPI NTLM)
	ldap+simple://TEST\\victim:<password>@10.10.10.2 (SASL SIMPLE auth)
	ldap+plain://TEST\\victim:<password>@10.10.10.2 (SASL SIMPLE auth)
	ldap+ntlm-password://TEST\\victim:<password>@10.10.10.2
	ldap+ntlm-nt://TEST\\victim:<nthash>@10.10.10.2
	ldap+kerberos-password://TEST\\victim:<password>@10.10.10.2
	ldap+kerberos-rc4://TEST\\victim:<rc4key>@10.10.10.2
	ldap+kerberos-aes://TEST\\victim:<aes>@10.10.10.2
	ldap://TEST\\victim:password@10.10.10.2/DC=test,DC=corp/
	ldap://TEST\\victim:password@10.10.10.2/DC=test,DC=corp/?timeout=99&proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080&proxytimeout=44
	"""
	
	def __init__(self, url):
		self.url = url
		self.ldap_scheme = None
		self.auth_scheme = None

		self.domain = None
		self.username = None
		self.password = None
		self.encrypt = False
		self.auth_settings = {}
		self.etypes = None

		self.ldap_proto = None
		self.ldap_host = None
		self.ldap_port = 389
		self.ldap_tree = None
		self.target_timeout = 5
		self.target_pagesize = 1000
		self.target_ratelimit = 0
		self.dc_ip = None
		self.serverip = None
		self.proxy = None

		self.__pwpreprocess = None

		self.parse()


	def get_credential(self):
		"""
		Creates a credential object
		
		:return: Credential object
		:rtype: :class:`MSLDAPCredential`
		"""
		t = MSLDAPCredential(
			domain=self.domain, 
			username=self.username, 
			password = self.password, 
			auth_method=self.auth_scheme, 
			settings = self.auth_settings
		)
		t.encrypt = self.encrypt
		t.etypes = self.etypes
		
		return t

	def get_target(self):
		"""
		Creates a target object
		
		:return: Target object
		:rtype: :class:`MSLDAPTarget`
		"""
		target = MSLDAPTarget(
			self.ldap_host, 
			port = self.ldap_port, 
			proto = self.ldap_scheme, 
			tree=self.ldap_tree,
			timeout = self.target_timeout,
			ldap_query_page_size = self.target_pagesize,
			ldap_query_ratelimit = self.target_ratelimit
		)
		target.domain = self.domain
		target.dc_ip = self.dc_ip
		target.proxy = self.proxy
		target.serverip = self.serverip
		return target

	def get_client(self):
		"""
		Creates a client that can be used to interface with the server
		
		:return: LDAP client
		:rtype: :class:`MSLDAPClient`
		"""
		cred = self.get_credential()
		target = self.get_target()
		return MSLDAPClient(target, cred)
	
	def get_connection(self):
		"""
		Creates a connection that can be used to interface with the server
		
		:return: LDAP connection
		:rtype: :class:`MSLDAPClientConnection`
		"""
		cred = self.get_credential()
		target = self.get_target()
		return MSLDAPClientConnection(target, cred)

	def scheme_decoder(self, scheme):
		schemes = []
		for item in scheme.upper().split('+'):
			schemes.append(item.replace('-','_'))

		if schemes[0] == 'LDAP':
			self.ldap_scheme = LDAPProtocol.TCP
			self.ldap_port = 389
		elif schemes[0] == 'LDAPS':
			self.ldap_scheme = LDAPProtocol.SSL
			self.ldap_port = 636
		elif schemes[0] == 'LDAP_SSL':
			self.ldap_scheme = LDAPProtocol.SSL
			self.ldap_port = 636
		elif schemes[0] == 'LDAP_TCP':
			self.ldap_scheme = LDAPProtocol.TCP
			self.ldap_port = 389
		elif schemes[0] == 'LDAP_UDP':
			self.ldap_scheme = LDAPProtocol.UDP
			self.ldap_port = 389
		else:
			raise Exception('Unknown protocol! %s' % schemes[0])
		
		if len(schemes) == 1:
			return
		
		try:
			x = PLAINTEXTSCHEME(schemes[1])
			if x == PLAINTEXTSCHEME.SIMPLE_PROMPT:
				self.auth_scheme = LDAPAuthProtocol.SIMPLE
				self.__pwpreprocess = 'PROMPT'

			if x == PLAINTEXTSCHEME.SIMPLE_HEX:
				self.auth_scheme = LDAPAuthProtocol.SIMPLE
				self.__pwpreprocess = 'HEX'

			if x == PLAINTEXTSCHEME.SIMPLE_B64:
				self.auth_scheme = LDAPAuthProtocol.SIMPLE
				self.__pwpreprocess = 'B64'

			if x == PLAINTEXTSCHEME.PLAIN_PROMPT:
				self.auth_scheme = LDAPAuthProtocol.PLAIN
				self.__pwpreprocess = 'PROMPT'

			if x == PLAINTEXTSCHEME.PLAIN_HEX:
				self.auth_scheme = LDAPAuthProtocol.PLAIN
				self.__pwpreprocess = 'HEX'

			if x == PLAINTEXTSCHEME.PLAIN_B64:
				self.auth_scheme = LDAPAuthProtocol.PLAIN
				self.__pwpreprocess = 'B64'

			if x == PLAINTEXTSCHEME.SICILY_PROMPT:
				self.auth_scheme = LDAPAuthProtocol.SICILY
				self.__pwpreprocess = 'PROMPT'

			if x == PLAINTEXTSCHEME.SICILY_HEX:
				self.auth_scheme = LDAPAuthProtocol.SICILY
				self.__pwpreprocess = 'HEX'

			if x == PLAINTEXTSCHEME.SICILY_B64:
				self.auth_scheme = LDAPAuthProtocol.SICILY
				self.__pwpreprocess = 'B64'

			if x == PLAINTEXTSCHEME.NTLM_PROMPT:
				self.auth_scheme = LDAPAuthProtocol.NTLM_PASSWORD
				self.__pwpreprocess = 'PROMPT'

			if x == PLAINTEXTSCHEME.NTLM_HEX:
				self.auth_scheme = LDAPAuthProtocol.NTLM_PASSWORD
				self.__pwpreprocess = 'HEX'

			if x == PLAINTEXTSCHEME.NTLM_B64:
				self.auth_scheme = LDAPAuthProtocol.NTLM_PASSWORD
				self.__pwpreprocess = 'B64'			
		except:
			try:
				self.auth_scheme = LDAPAuthProtocol(schemes[1])
			except:
				raise Exception('Uknown scheme!')
		
		return

	def parse(self):
		url_e = urlparse(self.url)
		self.scheme_decoder(url_e.scheme)

		self.password = url_e.password
		if self.__pwpreprocess is not None:
			if self.__pwpreprocess == 'PROMPT':
				self.password = getpass.getpass()

			elif self.__pwpreprocess == 'HEX':
				self.password = bytes.fromhex(self.password).decode()

			elif self.__pwpreprocess == 'B64':
				self.password = base64.b64decode(self.password).decode()

			else:
				raise Exception('Unknown password preprocess directive %s' % self.__pwpreprocess)


		if url_e.username is not None:
			if url_e.username.find('\\') != -1:
				self.domain , self.username = url_e.username.split('\\')
			else:
				self.domain = None
				self.username = url_e.username

		#defaulting schemes...
		if self.auth_scheme is None:
			if self.username is not None and self.domain is not None and self.password is not None:
				#tricky parsing to make user feel confortable...
				if len(self.password) == 32:
					try:
						bytes.fromhex(self.password)
						self.auth_scheme = LDAPAuthProtocol.NTLM_NT
					except:
						self.auth_scheme = LDAPAuthProtocol.NTLM_PASSWORD
				else:
					self.auth_scheme = LDAPAuthProtocol.NTLM_PASSWORD
			else:
				self.auth_scheme = LDAPAuthProtocol.SIMPLE

		self.ldap_host = url_e.hostname
		if url_e.port is not None:
			self.ldap_port = int(url_e.port)

		if url_e.path is not None:
			tree = url_e.path.replace('/','')
			if tree != '':
				self.ldap_tree = tree

		proxy_present = False
		if url_e.query is not None:
			query = parse_qs(url_e.query)
			if 'etype' in query:
				self.etypes = []
			for k in query:
				if k.startswith('proxy') is True:
					proxy_present = True
				if k == 'dc':
					self.dc_ip = query[k][0]
				elif k == 'timeout':
					self.timeout = int(query[k][0])
				elif k == 'serverip':
					self.serverip = query[k][0]
				elif k == 'dns':
					self.dns = query[k] #multiple dns can be set, so not trimming here
				elif k == 'encrypt':
					self.encrypt = bool(int(query[k][0]))
				elif k == 'etype':
					self.etypes = [int(x) for x in query[k]]
				elif k.startswith('auth'):
					self.auth_settings[k[len('auth'):]] = query[k]
				elif k == 'rate':
					self.target_ratelimit = float(query[k][0])
				elif k == 'pagesize':
					self.target_pagesize = int(query[k][0])
				#elif k.startswith('same'):
				#	self.auth_settings[k[len('same'):]] = query[k]

		if proxy_present is True:
			self.proxy = MSLDAPProxy.from_params(self.url)

		if self.auth_scheme in [LDAPAuthProtocol.SSPI_NTLM, LDAPAuthProtocol.SSPI_KERBEROS]:
			if platform.system().upper() != 'WINDOWS':
				raise Exception('SSPI auth only works on Windows!')
			if self.username is None:
				self.username = '<CURRENT>'
			if self.password is None:
				self.password = '<CURRENT>'
			if self.domain is None:
				self.domain = '<CURRENT>'

		if self.auth_scheme in MSLDAP_KERBEROS_PROTOCOLS and self.dc_ip is None:
			raise Exception('The "dc" parameter MUST be used for kerberos authentication types!')


#		if self.proxy_scheme in [LDAPProxyType.MULTIPLEXOR, LDAPProxyType.MULTIPLEXOR_SSL]:
#			if self.proxy_port is None:
#				self.proxy_port = 9999
#		
#		if self.proxy_scheme in [LDAPProxyType.MULTIPLEXOR, LDAPProxyType.MULTIPLEXOR_SSL]:
#			if 'agentid' not in self.proxy_settings:
#				raise Exception('multiplexor proxy reuires agentid to be set! Set it via proxyagentid parameter!')
#



		
if __name__ == '__main__':
	url_tests = [
		'ldap://10.10.10.2',
		'ldap://10.10.10.2:9999',
		'ldap://test:password@10.10.10.2',
		'ldap://domain\\test@10.10.10.2',
		'ldap://domain\\test:password@10.10.10.2:9999',
		'ldap://domain\\test:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@10.10.10.2:9999',
		'ldaps+sspi-ntlm://10.10.10.2',
		'ldaps+sspi-kerberos://10.10.10.2',
		'ldaps+ntlm-password://domain\\test:password@10.10.10.2:9999',
		'ldaps+ntlm-nt://domain\\test:password@10.10.10.2:9999',
		'ldaps+kerberos-password://domain\\test:password@10.10.10.2:9999',
		'ldaps://10.10.10.2:9999',
		'ldaps://test:password@10.10.10.2',
		'ldaps://domain\\test@10.10.10.2',
		'ldaps://domain\\test:password@10.10.10.2:9999',
		'ldaps://DOMAIN\\test:password@10.10.10.2:9999/?proxytype=socks5&proxyserver=127.0.0.1',
		'ldaps://DOMAIN\\test:password@10.10.10.2:9999/?proxytype=socks5&proxyserver=127.0.0.1&proxyuser=admin&proxypass=alma',
		'ldaps://DOMAIN\\test:password@10.10.10.2:9999/?proxytype=multiplexor&proxyserver=127.0.0.1&proxyport=9999&proxyuser=admin&proxypass=alma',
		'ldaps://10.10.10.2',
		'ldaps://10.10.10.2:6666',
	]
	for url in url_tests:
		print('===========================================================================')
		print(url)
		try:
			dec = MSLDAPURLDecoder(url)
			creds = dec.get_credential()
			target = dec.get_target()
		except Exception as e:
			import traceback
			traceback.print_exc()
			print('ERROR! Reason: %s' % e)
			input()
		else:
			print(str(creds))
			print(str(target))
			input()
