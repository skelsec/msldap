
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from asysocks.unicomm.common.target import UniTarget, UniProto

class MSLDAPTarget(UniTarget):
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
	:param dc_ip: Ip address of the kerberos server (if kerberos is used)
	:type dc_ip: str
	"""
	def __init__(self, ip, port = 389, protocol = UniProto.CLIENT_TCP, tree = None, proxies = None, timeout = 10, ldap_query_page_size = 1000, ldap_query_ratelimit = 0, dc_ip:str = None, domain:str = None, hostname:str = None):
		UniTarget.__init__(self, ip, port, protocol, timeout, hostname = hostname, proxies = proxies, domain = domain, dc_ip = dc_ip)
		self.tree = tree
		self.ldap_query_page_size = ldap_query_page_size
		self.ldap_query_ratelimit = ldap_query_ratelimit
	
	def to_target_string(self):
		return 'ldap/%s@%s' % (self.get_hostname_or_ip(), self.domain)  #ldap/WIN2019AD.test.corp @ TEST.CORP

	def get_host(self):
		if self.protocol == UniProto.CLIENT_SSL_TCP:
			proto = 'ldaps'
		elif self.protocol == UniProto.CLIENT_TCP:
			proto = 'ldap'
		return '%s://%s:%s' % (proto, self.get_hostname_or_ip(), self.port)

	def is_ssl(self):
		return self.protocol == UniProto.CLIENT_SSL_TCP
	
	def __str__(self):
		t = '==== MSLDAPTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t