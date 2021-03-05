
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum

import platform
try:
	import ssl
except:
	if platform.system() == 'Emscripten':
		pass

class LDAPProtocol(enum.Enum):
	TCP = 'TCP'
	UDP = 'UDP'
	SSL = 'SSL'


class MSLDAPTarget:
	"""
	Describes the connection to the server.
	
	:param host: IP address or hostname of the server
	:type host: str
	:param port: port of the LDAP service running on the server
	:type port: int
	:param proto: Connection protocol to be used
	:type proto: :class:`LDAPProtocol`
	:param tree: The tree to connect to
	:type tree: str
	:param proxy: specifies what kind of proxy to be used
	:type proxy: :class:`MSLDAPProxy`
	:param timeout: connection timeout in seconds
	:type timeout: int
	:param ldap_query_page_size: Maximum number of elements to fetch in each paged_query call.
	:type ldap_query_page_size: int
	:param ldap_query_ratelimit: rate limit of paged queries. This will cause a sleep (in seconds) between fetching of each page of the query
	:type ldap_query_ratelimit: float
	"""
	def __init__(self, host, port = 389, proto = LDAPProtocol.TCP, tree = None, proxy = None, timeout = 10, ldap_query_page_size = 1000, ldap_query_ratelimit = 0):
		self.proto = proto
		self.host = host
		self.tree = tree
		self.port = port
		self.proxy = proxy
		self.timeout = timeout
		self.dc_ip = None
		self.serverip = None
		self.domain = None
		self.sslctx = None
		self.ldap_query_page_size = ldap_query_page_size
		self.ldap_query_ratelimit = ldap_query_ratelimit

	def get_ssl_context(self):
		if self.proto == LDAPProtocol.SSL:
			if self.sslctx is None:
				# TODO ssl verification :)
				self.sslctx = ssl._create_unverified_context()
				#self.sslctx.verify = False
			return self.sslctx
		return None

	def to_target_string(self):
		return 'ldap/%s@%s' % (self.host,self.domain)  #ldap/WIN2019AD.test.corp @ TEST.CORP

	def get_host(self):
		return '%s://%s:%s' % (self.proto, self.host, self.port)

	def is_ssl(self):
		return self.proto == LDAPProtocol.SSL
	
	def __str__(self):
		t = '==== MSLDAPTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t