#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum

from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, BASE, ALL_ATTRIBUTES
				
class LDAPAuthProtocol(enum.Enum):
	ANONYMOUS = 'ANONYMOUS'
	PLAIN = 'PLAIN'
	NTLM = 'NTLM'
	SSPI = 'SSPI'
	MULTIPLEXOR = 'MULTIPLEXOR'
	MULTIPLEXOR_SSL = 'MULTIPLEXOR_SSL'


class MSLDAPCredential:
	def __init__(self, domain=None, username= None, password = None, auth_method = None, settings = None):
		self.auth_method = auth_method
		self.domain   = domain
		self.username = username
		self.password = password
		self.settings = settings

	def get_msuser(self):
		if not self.domain:
			return self.username

		return '%s\\%s' % (self.domain,self.username)

	def get_authmethod(self):
		if self.auth_method in [LDAPAuthProtocol.NTLM, LDAPAuthProtocol.SSPI, LDAPAuthProtocol.MULTIPLEXOR, LDAPAuthProtocol.MULTIPLEXOR_SSL]:
			return NTLM
		return SIMPLE
		
	def is_anonymous(self):
		return self.auth_method == LDAPAuthProtocol.ANONYMOUS
		

	def __str__(self):
		t = '==== MSLDAPCredential ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
