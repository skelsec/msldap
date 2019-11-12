
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum
from urllib.parse import urlparse, parse_qs


class LDAPProtocol(enum.Enum):
	LDAP = 'LDAP'
	LDAPS = 'LDAPS'


class MSLDAPTarget:
	def __init__(self, host, port = 389, proto = 'ldap', tree = None, proxy = None, timeout = 5):
		self.proto = proto
		self.host = host
		self.tree = tree
		self.port = port
		self.proxy = proxy
		self.timeout = timeout

	def get_host(self):
		return '%s://%s:%s' % (self.proto, self.host, self.port)

	def is_ssl(self):
		return self.proto.lower() == 'ldaps'
		
		
	@staticmethod
	def from_connection_string(s):
		"""
		Credential input format:
		<domain>/<username>/<secret_type>:<secret>@<dc_ip_or_hostname_or_ldap_url>
		"""
		
		_ , conn = s.rsplit('@', 1)
		if conn.find('://') != -1:
			o = urlparse(conn)
			if o.netloc.find(':') != -1:
				host, port = o.netloc.split(':')
			else:
				host = o.netloc
				port = 389
			return MSLDAPTarget(host, port = port, proto = o.scheme)
		else:
			if conn.find(':') != -1:
				host, port = conn.split(':')
			else:
				host = conn
				port = 389
			
			return MSLDAPTarget(host, port = port)
	
	def __str__(self):
		t = '==== MSLDAPTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t