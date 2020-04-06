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
	KERBEROS_RC4 = 'KERBEROS_RC4' #actually SASL-GSSAPI-SPNEGO-KERBEROS
	KERBEROS_NT = 'KERBEROS_NT' #actually SASL-GSSAPI-SPNEGO-KERBEROS
	KERBEROS_AES = 'KERBEROS_AES' #actually SASL-GSSAPI-SPNEGO-KERBEROS
	KERBEROS_PASSWORD = 'KERBEROS_PASSWORD' #actually SASL-GSSAPI-SPNEGO-KERBEROS
	KERBEROS_CCACHE = 'KERBEROS_CCACHE' #actually SASL-GSSAPI-SPNEGO-KERBEROS
	KERBEROS_KEYTAB = 'KERBEROS_KEYTAB' #actually SASL-GSSAPI-SPNEGO-KERBEROS
	MULTIPLEXOR = 'MULTIPLEXOR'
	MULTIPLEXOR_SSL = 'MULTIPLEXOR_SSL'
	SSPI_NTLM = 'SSPI_NTLM' #actually SASL-GSSAPI-SPNEGO-NTLM but with integrated SSPI
	SSPI_KERBEROS = 'SSPI_KERBEROS' #actually SASL-GSSAPI-SPNEGO-KERBEROS but with integrated SSPI

MSLDAP_GSS_METHODS = [
		LDAPAuthProtocol.NTLM_PASSWORD ,
		LDAPAuthProtocol.NTLM_NT ,
		LDAPAuthProtocol.KERBEROS_RC4 ,
		LDAPAuthProtocol.KERBEROS_NT ,
		LDAPAuthProtocol.KERBEROS_AES ,
		LDAPAuthProtocol.KERBEROS_PASSWORD ,
		LDAPAuthProtocol.KERBEROS_CCACHE ,
		LDAPAuthProtocol.KERBEROS_KEYTAB ,
		LDAPAuthProtocol.SSPI_NTLM ,
		LDAPAuthProtocol.SSPI_KERBEROS,
	
]

MSLDAP_KERBEROS_PROTOCOLS = [
	LDAPAuthProtocol.KERBEROS_RC4 ,
	LDAPAuthProtocol.KERBEROS_NT ,
	LDAPAuthProtocol.KERBEROS_AES ,
	LDAPAuthProtocol.KERBEROS_PASSWORD ,
	LDAPAuthProtocol.KERBEROS_CCACHE ,
	LDAPAuthProtocol.KERBEROS_KEYTAB ,
]

class MSLDAPCredential:
	def __init__(self, domain=None, username= None, password = None, auth_method = None, settings = None):
		self.auth_method = auth_method
		self.domain   = domain
		self.username = username
		self.password = password
		self.signing_preferred = False
		self.encryption_preferred = False
		self.settings = settings
		self.etypes = None

	def get_msuser(self):
		if not self.domain:
			return self.username

		return '%s\\%s' % (self.domain,self.username)		

	def __str__(self):
		t = '==== MSLDAPCredential ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t

