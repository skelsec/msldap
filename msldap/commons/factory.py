
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import enum
import copy

from msldap.commons.target import MSLDAPTarget
from msldap.client import MSLDAPClient
from msldap.connection import MSLDAPClientConnection
from asyauth.common.credentials import UniCredential

class LDAPConnectionFactory:
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
	
	def __init__(self, credential:UniCredential = None, target:MSLDAPTarget = None ):
		self.credential = credential
		self.target = target

	@staticmethod
	def from_url(connection_url):
		target = MSLDAPTarget.from_url(connection_url)
		credential = UniCredential.from_url(connection_url)
		return LDAPConnectionFactory(credential, target)

	def get_credential(self) -> UniCredential:
		"""
		Creates a credential object
		
		:return: Credential object
		:rtype: :class:`UniCredential`
		"""
		return copy.deepcopy(self.credential)

	def get_target(self) -> MSLDAPTarget:
		"""
		Creates a target object
		
		:return: Target object
		:rtype: :class:`MSLDAPTarget`
		"""
		return copy.deepcopy(self.target)

	def get_client(self) -> MSLDAPClient:
		"""
		Creates a client that can be used to interface with the server
		
		:return: LDAP client
		:rtype: :class:`MSLDAPClient`
		"""
		cred = self.get_credential()
		target = self.get_target()
		return MSLDAPClient(target, cred)


	def get_connection(self) -> MSLDAPClientConnection:
		"""
		Creates a connection that can be used to interface with the server
		
		:return: LDAP connection
		:rtype: :class:`MSLDAPClientConnection`
		"""
		cred = self.get_credential()
		target = self.get_target()
		return MSLDAPClientConnection(target, cred)
	
	@staticmethod
	def from_ldapconnection(connection:MSLDAPClientConnection):
		"""Creates a new LDAPConnectionFactory object from an existing SMBConnection object"""
		"""This is useful when you have a connection object, but you need to create a new connection with the same credentials"""
		return LDAPConnectionFactory(copy.deepcopy(connection.credential), copy.deepcopy(connection.target))

		
	def __str__(self):
		t = '==== LDAPConnectionFactory ====\r\n'
		for k in self.__dict__:
			val = self.__dict__[k]
			if isinstance(val, enum.IntFlag):
				val = val
			elif isinstance(val, enum.Enum):
				val = val.name
			
			t += '%s: %s\r\n' % (k, str(val))
			
		return t

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
			dec = LDAPConnectionFactory.from_url(url)
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
