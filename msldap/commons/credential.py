#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum

# https://tools.ietf.org/html/rfc4513
# simple auth: 
# 	- anonymous
#   - user without password
# 	- username + password
#
# SASL:
#   - plain
#   - gssapi
#		-SSPI
#			- NTLM
#			- KERBEROS
# Sicily:
#   - NTLM
# Multiplexor
#		

class LDAPAuthProtocol(enum.Enum):
	SIMPLE = 'SIMPLE' #SIMPLE can be with no creds - anonymous bind
	PLAIN = 'PLAIN' #actually SASL-PLAIN
	SICILY = 'SICILY' #NTLM (old proprietary from MS)
	NTLM_PASSWORD = 'NTLM_PASSWORD' #actually SASL-GSSAPI-SPNEGO-NTLM
	NTLM_NT = 'NTLM_NT' #actually SASL-GSSAPI-SPNEGO-NTLM
	KERBEROS_RC4 = 'KERBEROS_RC4' 
	KERBEROS_NT = 'KERBEROS_NT' 
	KERBEROS_AES = 'KERBEROS_AES' 
	KERBEROS_PASSWORD = 'KERBEROS_PASSWORD' 
	KERBEROS_CCACHE = 'KERBEROS_CCACHE' 
	KERBEROS_KEYTAB = 'KERBEROS_KEYTAB'
	KERBEROS_KIRBI = 'KERBEROS_KIRBI' 
	MULTIPLEXOR_KERBEROS = 'MULTIPLEXOR_KERBEROS'
	MULTIPLEXOR_NTLM = 'MULTIPLEXOR_NTLM'
	MULTIPLEXOR_SSL_KERBEROS = 'MULTIPLEXOR_SSL_KERBEROS'
	MULTIPLEXOR_SSL_NTLM = 'MULTIPLEXOR_SSL_NTLM'
	SSPI_NTLM = 'SSPI_NTLM' #actually SASL-GSSAPI-SPNEGO-NTLM but with integrated SSPI
	SSPI_KERBEROS = 'SSPI_KERBEROS' #actually SASL-GSSAPI-SPNEGO-KERBEROS but with integrated SSPI
	WSNET_NTLM = 'WSNET_NTLM'
	WSNET_KERBEROS = 'WSNET_KERBEROS'
	SSPIPROXY_NTLM = 'SSPIPROXY_NTLM'
	SSPIPROXY_KERBEROS = 'SSPIPROXY_KERBEROS'

MSLDAP_GSS_METHODS = [
		LDAPAuthProtocol.NTLM_PASSWORD ,
		LDAPAuthProtocol.NTLM_NT ,
		LDAPAuthProtocol.KERBEROS_RC4 ,
		LDAPAuthProtocol.KERBEROS_NT ,
		LDAPAuthProtocol.KERBEROS_AES ,
		LDAPAuthProtocol.KERBEROS_PASSWORD ,
		LDAPAuthProtocol.KERBEROS_CCACHE ,
		LDAPAuthProtocol.KERBEROS_KEYTAB ,
		LDAPAuthProtocol.KERBEROS_KIRBI ,
		LDAPAuthProtocol.SSPI_NTLM ,
		LDAPAuthProtocol.SSPI_KERBEROS,
		LDAPAuthProtocol.MULTIPLEXOR_KERBEROS,
		LDAPAuthProtocol.MULTIPLEXOR_NTLM,
		LDAPAuthProtocol.MULTIPLEXOR_SSL_KERBEROS,
		LDAPAuthProtocol.MULTIPLEXOR_SSL_NTLM,
		LDAPAuthProtocol.WSNET_NTLM,
		LDAPAuthProtocol.WSNET_KERBEROS,
		LDAPAuthProtocol.SSPIPROXY_NTLM,
		LDAPAuthProtocol.SSPIPROXY_KERBEROS,
]

MSLDAP_KERBEROS_PROTOCOLS = [
	LDAPAuthProtocol.KERBEROS_RC4 ,
	LDAPAuthProtocol.KERBEROS_NT ,
	LDAPAuthProtocol.KERBEROS_AES ,
	LDAPAuthProtocol.KERBEROS_PASSWORD ,
	LDAPAuthProtocol.KERBEROS_CCACHE ,
	LDAPAuthProtocol.KERBEROS_KEYTAB ,
	LDAPAuthProtocol.KERBEROS_KIRBI ,
]

class MSLDAPCredential:
	"""
	Describes the user's credentials to be used for authentication during the bind operation.
	
	:param domain: Domain of the user
	:type domain: str
	:param username: Username of the user
	:type username: str
	:param password: The authentication secret. The actual contents depend on the `auth_method`
	:type password: str
	:param auth_method: The ahtentication method to be performed during bind operation
	:type auth_method: :class:`LDAPAuthProtocol`
	:param settings: Additional settings
	:type settings: dict
	:param etypes: Supported encryption types for Kerberos authentication.
	:type etypes: List[:class:`int`]
	:param encrypt: Use protocol-level encryption. Doesnt work on LDAPS
	:type encrypt: bool
	"""
	def __init__(self, domain=None, username= None, password = None, auth_method = None, settings = None, etypes = None, encrypt = False):
		self.auth_method = auth_method
		self.domain   = domain
		self.username = username
		self.password = password
		self.signing_preferred = False
		self.encryption_preferred = False
		self.settings = settings
		self.etypes = etypes
		self.encrypt = encrypt

	def get_msuser(self):
		if not self.domain:
			return self.username

		return '%s\\%s' % (self.domain,self.username)		

	def __str__(self):
		t = '==== MSLDAPCredential ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t

