
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import platform
import hashlib
from urllib.parse import urlparse, parse_qs

from msldap.commons.credential import MSLDAPCredential, LDAPAuthProtocol
from msldap.commons.target import MSLDAPTarget, LDAPProtocol
from msldap.commons.proxy import MSLDAPProxy, MSLDAPProxyType
from msldap.client import MSLDAPClient


class MSLDAPURLDecoder:

	help_epilog = """
	MSLDAP URL Format: <protocol>+<auth>://<username>:<password>@<ip_or_host>:<port>/<tree>/?<param>=<value>
	<protocol> sets the ldap protocol following values supported:
		- ldap
		- ldaps
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
	ldap://10.10.10.2 (anonymous bind)
	ldaps://test.corp (anonymous bind)
	ldap+sspi:///test.corp 
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
		self.auth_settings = {}

		self.ldap_proto = None
		self.ldap_host = None
		self.ldap_port = 389
		self.ldap_tree = None
		self.target_timeout = 5
		self.target_pagesize = 1000
		self.dc_ip = None
		self.serverip = None
		self.proxy = None

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
			proto = self.ldap_scheme, 
			tree=self.ldap_tree,
			timeout = self.target_timeout	
		)
		target.domain = self.domain
		target.dc_ip = self.dc_ip
		target.proxy = self.proxy
		return target

	def get_client(self):
		cred = self.get_credential()
		target = self.get_target()
		return MSLDAPClient(target, cred, ldap_query_page_size = self.target_pagesize)

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
			self.auth_scheme = LDAPAuthProtocol(schemes[1])
		except:
			raise Exception('Uknown scheme!')
		
		return

	def parse(self):
		url_e = urlparse(self.url)
		self.scheme_decoder(url_e.scheme)

		self.password = url_e.password

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
			for k in query:
				if k.startswith('proxy') is True:
					proxy_present = True
				if k == 'dc':
					self.dc_ip = query[k][0]
				elif k == 'timeout':
					self.timeout = int(query[k][0])
				elif k == 'serverip':
					self.server_ip = query[k][0]
				elif k == 'dns':
					self.dns = query[k] #multiple dns can be set, so not trimming here
				elif k.startswith('auth'):
					self.auth_settings[k[len('auth'):]] = query[k]
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



#
#		if self.auth_scheme == LDAPAuthProtocol.SSPI:
#			if self.username is None:
#				self.username = '<CURRENT>'
#			if self.password is None:
#				self.password = '<CURRENT>'
#			if self.domain is None:
#				self.domain = '<CURRENT>'
#
#		if self.auth_scheme == LDAPAuthProtocol.NTLM:
#			if len(self.password) == 32:
#				try:
#					bytes.fromhex(self.password)
#				except:
#					a = hashlib.new('md4')
#					a.update(self.password.encode('utf-16-le'))
#					hs = a.hexdigest()
#					self.password = '%s:%s' % (hs, hs)
#				else:
#					self.password = '%s:%s' % (self.password, self.password)
#			else:
#				a = hashlib.new('md4')
#				a.update(self.password.encode('utf-16-le'))
#				hs = a.hexdigest()
#				self.password = '%s:%s' % (hs, hs)

#
#		#now for the url parameters
#		"""
#		ldaps://user:pass@10.10.10.2/?proxyhost=127.0.0.1&proxyport=8888&proxyuser=dddd&proxypass=ssss&dns=127.0.0.1
#		"""
#		if url_e.query is not None:
#			query = parse_qs(url_e.query)
#			for k in query:
#				if k == 'dns':
#					self.dns = query[k] #multiple dns can be set, so not trimming here
#				elif k.startswith('auth'):
#					self.auth_settings[k[len('auth'):]] = query[k] #the result is a list for each entry because this preprocessor is not aware which elements should be lists!
#				elif k == 'timeout':
#					self.target_timeout = int(query[k][0])
#				elif k == 'pagesize':
#					self.target_pagesize = int(query[k][0])
#				elif k.startswith('proxy'):
#					if k == 'proxytype':
#						self.proxy_scheme = LDAPProxyType(query[k][0].upper())
#					elif k == 'proxyhost':
#						self.proxy_ip = query[k][0]
#					elif k == 'proxyuser':
#						if query[k][0].find('\\') != -1:
#							self.proxy_domain, self.proxy_username = query[k][0].split('\\')
#						else:
#							self.proxy_username = query[k][0]
#					elif k == 'proxypass':
#						self.proxy_password = query[k][0]
#					elif k == 'proxytimeout':
#						self.proxy_timeout = int(query[k][0])
#					elif k == 'proxyport':
#						self.proxy_port = int(query[k][0])
#					else:
#						self.proxy_settings[k[len('proxy'):]] = query[k] #the result is a list for each entry because this preprocessor is not aware which elements should be lists!
#
#				#####TODOOOO FIX THIS!!!!
#				elif k.startswith('same'):
#					self.auth_settings[k[len('same'):]] = query[k]
#					if k == 'sametype':
#						self.proxy_scheme = LDAPProxyType(query[k][0].upper())
#					elif k == 'samehost':
#						self.proxy_ip = query[k][0]
#					elif k == 'sametimeout':
#						self.proxy_timeout = int(query[k][0])
#					elif k == 'sameuser':
#						if query[k][0].find('\\') != -1:
#							self.proxy_domain, self.proxy_username = query[k][0].split('\\')
#						else:
#							self.proxy_username = query[k][0]
#					elif k == 'samepass':
#						self.proxy_password = query[k][0]
#					elif k == 'sameport':
#						self.proxy_port = int(query[k][0])
#					else:
#						self.proxy_settings[k[len('same'):]] = query[k] #the result is a list for each entry because this preprocessor is not aware which elements should be lists!
#		
#		#setting default proxy ports
#		if self.proxy_scheme in [LDAPProxyType.SOCKS5, LDAPProxyType.SOCKS5_SSL]:
#			if self.proxy_port is None:
#				self.proxy_port = 1080
#		
#		if self.proxy_scheme in [LDAPProxyType.MULTIPLEXOR, LDAPProxyType.MULTIPLEXOR_SSL]:
#			if self.proxy_port is None:
#				self.proxy_port = 9999
#
#		#sanity checks...
#		if self.proxy_scheme is not None:
#			if self.proxy_ip is None:
#				raise Exception('proxyserver MUST be provided if using proxy')
#		
#		if self.proxy_scheme in [LDAPProxyType.MULTIPLEXOR, LDAPProxyType.MULTIPLEXOR_SSL]:
#			if 'agentid' not in self.proxy_settings:
#				raise Exception('multiplexor proxy reuires agentid to be set! Set it via proxyagentid parameter!')
#
#		if self.auth_scheme in [LDAPAuthProtocol.PLAIN, LDAPAuthProtocol.NTLM, LDAPAuthProtocol.SSPI]:
#			if self.username is None:
#				raise Exception('For authentication protocol %s the username MUST be specified!' % self.auth_scheme.value)
#			if self.password is None:
#				raise Exception('For authentication protocol %s the password MUST be specified!' % self.auth_scheme.value)
#		
#		if self.auth_scheme is None:
#			if self.username is None and self.password is None:
#				self.auth_scheme = LDAPAuthProtocol.ANONYMOUS
#			else:
#				raise Exception('Could not parse authentication protocol!')


		
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
