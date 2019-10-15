
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum

class LDAPProxyType(enum.Enum):
	SOCKS5 = 'SOCKS5'
	SOCKS5_SSL = 'SOCKS5_SSL'
	MULTIPLEXOR = 'MULTIPLEXOR'
	MULTIPLEXOR_SSL = 'MULTIPLEXOR_SSL'

class MSLDAPProxy:
	def __init__(self):
		self.ip = None
		self.port = 1080
		self.timeout = 10
		self.proxy_type = None
		self.username = None
		self.domain = None
		self.secret = None
		self.secret_type = None
		self.settings = {}
		
	def __str__(self):
		t = '==== MSLDAPProxy ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
		


