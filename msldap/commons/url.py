
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import hashlib
from urllib.parse import urlparse, parse_qs

from msldap.commons.credential import MSLDAPCredential, LDAPAuthProtocol
from msldap.commons.target import MSLDAPTarget, LDAPProtocol
from msldap.commons.proxy import MSLDAPProxy, LDAPProxyType
from msldap.connection import MSLDAPConnection


class MSLDAPURLDecoder:

	help_epilog = """
	MSLDAP URL Format: <protocol>+<auth>://<username>:<password>@<ip_or_host>:<port>/<tree>/?<param>=<value>
	<protocol> sets the ldap protocol following values supported:
		- ldap
		- ldaps (ldap over SSL) << known to be problematic because of the underlying library (ldap3)
	<auth> can be omitted if plaintext authentication is to be performed, otherwise:
		- ntlm
		- sspi (windows only!)
		- anonymous
		- plain
	<param> can be:
		- timeout : connction timeout in seconds
		- proxytype: currently only socks5 proxy is supported
		- proxyhost: Ip or hostname of the proxy server
		- proxyport: port of the proxy server
		- proxytimeout: timeout ins ecodns for the proxy connection

	Examples:
	ldap://10.10.10.2
	ldaps://test.corp
	ldap+sspi:///test.corp
	ldap+ntlm://TEST\\victim:password@10.10.10.2
	ldap://TEST\\victim:password@10.10.10.2/DC=test,DC=corp/
	ldap://TEST\\victim:password@10.10.10.2/DC=test,DC=corp/?timeout=99&proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080&proxytimeout=44
	"""
	
	def __init__(self, url):
		self.url = url
		self.ldap_scheme = None
		self.auth_scheme = None
		self.proxy_scheme = None

		self.domain = None
		self.username = None
		self.password = None
		self.auth_settings = {}

		self.ldap_proto = None
		self.ldap_host = None
		self.ldap_port = None
		self.ldap_tree = None
		self.target_timeout = 5
		self.target_pagesize = 1000

		self.proxy_domain = None
		self.proxy_username = None
		self.proxy_password = None
		self.proxy_scheme = None
		self.proxy_ip = None
		self.proxy_port = None
		self.proxy_settings = {}
		self.proxy_timeout = 5

		self.parse()


	def get_credential(self):
		return MSLDAPCredential(
			domain=self.domain, 
			username=self.username, 
			password = self.password, 
			auth_method=self.auth_scheme, 
			settings = self.auth_settings
		)

	def get_target(self):
		target = MSLDAPTarget(
			self.ldap_host, 
			port = self.ldap_port, 
			proto = self.ldap_proto.lower(), 
			tree=self.ldap_tree,
			timeout = self.target_timeout	
		)
		if self.proxy_scheme is not None:
			proxy = MSLDAPProxy()
			proxy.ip = self.proxy_ip
			proxy.port = self.proxy_port
			proxy.timeout = 10
			proxy.proxy_type = self.proxy_scheme
			proxy.username = self.proxy_username
			proxy.domain = self.proxy_domain
			proxy.settings = self.proxy_settings
			proxy.timeout = self.proxy_timeout

			target.proxy = proxy
		return target

	def get_connection(self):
		cred = self.get_credential()
		target = self.get_target()
		return MSLDAPConnection(cred, target, ldap_query_page_size = self.target_pagesize)

	def scheme_decoder(self, scheme):
		schemes = scheme.upper().split('+')
		self.ldap_scheme = LDAPProtocol(schemes[0])
		self.ldap_proto = self.ldap_scheme.value.lower()

		if len(schemes) == 1:
			return
		
		try:
			self.auth_scheme = LDAPAuthProtocol(schemes[1])
		except:
			raise Exception('Uknown scheme!')
		
		return

	def parse(self):
		url_e = urlparse(self.url)
		self.scheme_decoder(url_e.scheme)

		
		if url_e.username is not None:
			if url_e.username.find('\\') != -1:
				self.domain , self.username = url_e.username.split('\\')
			else:
				self.domain = None
				self.username = url_e.username

			if self.auth_scheme is None:
				self.auth_scheme = LDAPAuthProtocol.PLAIN

		self.password = url_e.password			

		if self.auth_scheme == LDAPAuthProtocol.SSPI:
			if self.username is None:
				self.username = '<CURRENT>'
			if self.password is None:
				self.password = '<CURRENT>'
			if self.domain is None:
				self.domain = '<CURRENT>'

		if self.auth_scheme == LDAPAuthProtocol.NTLM:
			if len(self.password) == 32:
				try:
					bytes.fromhex(self.password)
				except:
					a = hashlib.new('md4')
					a.update(self.password.encode('utf-16-le'))
					hs = a.hexdigest()
					self.password = '%s:%s' % (hs, hs)
				else:
					self.password = '%s:%s' % (self.password, self.password)
			else:
				a = hashlib.new('md4')
				a.update(self.password.encode('utf-16-le'))
				hs = a.hexdigest()
				self.password = '%s:%s' % (hs, hs)
		self.ldap_host = url_e.hostname
		if url_e.port is not None:
			self.ldap_port = int(url_e.port)
		else:
			if self.ldap_scheme == LDAPProtocol.LDAP:
				self.ldap_port = 389
			else:
				self.ldap_port = 636

		if url_e.path is not None:
			tree = url_e.path.replace('/','')
			if tree != '':
				self.ldap_tree = tree

		#now for the url parameters
		"""
		ldaps://user:pass@10.10.10.2/?proxyhost=127.0.0.1&proxyport=8888&proxyuser=dddd&proxypass=ssss&dns=127.0.0.1
		"""
		if url_e.query is not None:
			query = parse_qs(url_e.query)
			for k in query:
				if k == 'dns':
					self.dns = query[k] #multiple dns can be set, so not trimming here
				elif k.startswith('auth'):
					self.auth_settings[k[len('auth'):]] = query[k] #the result is a list for each entry because this preprocessor is not aware which elements should be lists!
				elif k == 'timeout':
					self.target_timeout = int(query[k][0])
				elif k == 'pagesize':
					self.target_pagesize = int(query[k][0])
				elif k.startswith('proxy'):
					if k == 'proxytype':
						self.proxy_scheme = LDAPProxyType(query[k][0].upper())
					elif k == 'proxyhost':
						self.proxy_ip = query[k][0]
					elif k == 'proxyuser':
						if query[k][0].find('\\') != -1:
							self.proxy_domain, self.proxy_username = query[k][0].split('\\')
						else:
							self.proxy_username = query[k][0]
					elif k == 'proxypass':
						self.proxy_password = query[k][0]
					elif k == 'proxytimeout':
						self.proxy_timeout = int(query[k][0])
					elif k == 'proxyport':
						self.proxy_port = int(query[k][0])
					else:
						self.proxy_settings[k[len('proxy'):]] = query[k] #the result is a list for each entry because this preprocessor is not aware which elements should be lists!

				#####TODOOOO FIX THIS!!!!
				elif k.startswith('same'):
					self.auth_settings[k[len('same'):]] = query[k]
					if k == 'sametype':
						self.proxy_scheme = LDAPProxyType(query[k][0].upper())
					elif k == 'samehost':
						self.proxy_ip = query[k][0]
					elif k == 'sametimeout':
						self.proxy_timeout = int(query[k][0])
					elif k == 'sameuser':
						if query[k][0].find('\\') != -1:
							self.proxy_domain, self.proxy_username = query[k][0].split('\\')
						else:
							self.proxy_username = query[k][0]
					elif k == 'samepass':
						self.proxy_password = query[k][0]
					elif k == 'sameport':
						self.proxy_port = int(query[k][0])
					else:
						self.proxy_settings[k[len('same'):]] = query[k] #the result is a list for each entry because this preprocessor is not aware which elements should be lists!
		
		#setting default proxy ports
		if self.proxy_scheme in [LDAPProxyType.SOCKS5, LDAPProxyType.SOCKS5_SSL]:
			if self.proxy_port is None:
				self.proxy_port = 1080
		
		if self.proxy_scheme in [LDAPProxyType.MULTIPLEXOR, LDAPProxyType.MULTIPLEXOR_SSL]:
			if self.proxy_port is None:
				self.proxy_port = 9999

		#sanity checks...
		if self.proxy_scheme is not None:
			if self.proxy_ip is None:
				raise Exception('proxyserver MUST be provided if using proxy')
		
		if self.proxy_scheme in [LDAPProxyType.MULTIPLEXOR, LDAPProxyType.MULTIPLEXOR_SSL]:
			if 'agentid' not in self.proxy_settings:
				raise Exception('multiplexor proxy reuires agentid to be set! Set it via proxyagentid parameter!')

		if self.auth_scheme in [LDAPAuthProtocol.PLAIN, LDAPAuthProtocol.NTLM, LDAPAuthProtocol.SSPI]:
			if self.username is None:
				raise Exception('For authentication protocol %s the username MUST be specified!' % self.auth_scheme.value)
			if self.password is None:
				raise Exception('For authentication protocol %s the password MUST be specified!' % self.auth_scheme.value)
		
		if self.auth_scheme is None:
			if self.username is None and self.password is None:
				self.auth_scheme = LDAPAuthProtocol.ANONYMOUS
			else:
				raise Exception('Could not parse authentication protocol!')


		
if __name__ == '__main__':
	url_tests = [
		'ldap://10.10.10.2',
		'ldap://10.10.10.2:9999',
		'ldap://test:password@10.10.10.2',
		'ldap://domain\\test@10.10.10.2', #this must fail!
		'ldap://domain\\test:password@10.10.10.2:9999',
		'ldaps+sspi://10.10.10.2',
		'ldaps://10.10.10.2:9999',
		'ldaps://test:password@10.10.10.2',
		'ldaps://domain\\test@10.10.10.2',
		'ldaps://domain\\test:password@10.10.10.2:9999',
		'ldaps://DOMAIN\\test:password@10.10.10.2:9999/?proxytype=socks5&proxyserver=127.0.0.1',
		'ldaps://DOMAIN\\test:password@10.10.10.2:9999/?proxytype=socks5&proxyserver=127.0.0.1&proxyuser=admin&proxypass=alma',
		'ldaps://DOMAIN\\test:password@10.10.10.2:9999/?proxytype=multiplexor&proxyserver=127.0.0.1&proxyport=9999&proxyuser=admin&proxypass=alma',
		'ldaps://10.10.10.2',
		'ldaps://10.10.10.2:6666',
		'ldaps+ntlm://DOMAIN\\test:password@10.10.10.2/?proxytype=socks5&proxyserver=127.0.0.1',
		'ldaps+sspi://domain\\test:password@10.10.10.2:9999',
		'ldaps+sspi://10.10.10.2:9999',
		'ldaps+sspi://domain\\test@10.10.10.2:9999',
		'ldap+multiplexor://10.10.10.2/?proxytype=multiplexor&proxyserver=127.0.0.1&proxyport=9999&proxyagentid=477532db-348c-4d3e-9a4d-4f86d38986dc&authip=127.0.0.1&authport=9999&authagentid=477532db-348c-4d3e-9a4d-4f86d38986dc'

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
