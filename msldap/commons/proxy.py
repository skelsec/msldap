
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum
from urllib.parse import urlparse, parse_qs

from asysocks.common.clienturl import SocksClientURL 

class MSLDAPProxyType(enum.Enum):
	SOCKS4 = 'SOCKS4'
	SOCKS4_SSL = 'SOCKS4_SSL'
	SOCKS5 = 'SOCKS5'
	SOCKS5_SSL = 'SOCKS5_SSL'
	MULTIPLEXOR = 'MULTIPLEXOR'
	MULTIPLEXOR_SSL = 'MULTIPLEXOR_SSL'
	WSNET = 'WSNET'
	WSNETWS = 'WSNETWS'
	WSNETWSS = 'WSNETWSS'

class MSLDAPProxy:
	"""
	Describes the proxy to be used when connecting to the server. Used as a parameter to the `MSLDAPTarget` object
	
	:param type: Specifies the proxy type
	:type type: :class:`MSLDAPProxyType`
	:param target: 
	:type target: 
	:param auth: Specifies the proxy authentication if any
	:type auth: 
	"""
	def __init__(self, type = None, target = None, auth = None):
		self.type = type
		self.target = target
		self.auth = auth


	@staticmethod
	def from_params(url_str):
		"""
		Creates a proxy object from the parameters found in an LDAP URL string

		:param type: url_str
		:type type: str
		:return: The proxy object 
		:rtype: :class:`MSLDAPProxy`
		"""
		proxy = MSLDAPProxy()
		url = urlparse(url_str)
		if url.query is None:
			return None

		query = parse_qs(url.query)
		if 'proxytype' not in query and 'sametype' not in query:
			return None
		
		proxy.type = MSLDAPProxyType(query['proxytype'][0].upper())
		if proxy.type in [MSLDAPProxyType.WSNET, MSLDAPProxyType.WSNETWS, MSLDAPProxyType.WSNETWSS,MSLDAPProxyType.SOCKS4, MSLDAPProxyType.SOCKS4_SSL, MSLDAPProxyType.SOCKS5, MSLDAPProxyType.SOCKS5_SSL]:
			proxy.target = SocksClientURL.from_params(url_str)
		else:
			proxy.target  = MSLDAPMultiplexorProxy.from_params(url_str)
		
		return proxy

	def __str__(self):
		t = '==== MSLDAPProxy ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t


class MSLDAPMultiplexorProxy:
	def __init__(self):
		self.ip = None
		self.port = None
		self.timeout = 10
		self.type = MSLDAPProxyType.MULTIPLEXOR
		self.username = None
		self.password = None
		self.domain = None
		self.agent_id = None
		self.virtual_socks_port = None
		self.virtual_socks_ip = None
	
	def sanity_check(self):
		if self.ip is None:
			raise Exception('MULTIPLEXOR server IP is missing!')
		if self.port is None:
			raise Exception('MULTIPLEXOR server port is missing!')
		if self.agent_id is None:
				raise Exception('MULTIPLEXOR proxy requires agentid to be set!')

	def get_server_url(self):
		con_str = 'ws://%s:%s' % (self.ip, self.port)
		if self.type == MSLDAPProxyType.MULTIPLEXOR_SSL:
			con_str = 'wss://%s:%s' % (self.ip, self.port)
		return con_str

	@staticmethod
	def from_params(url_str):
		res = MSLDAPMultiplexorProxy()
		url = urlparse(url_str)
		res.endpoint_ip = url.hostname
		if url.port:
			res.endpoint_port = int(url.port)
		if url.query is not None:
			query = parse_qs(url.query)

			for k in query:
				if k.startswith('proxy'):
					if k[5:] in multiplexorproxyurl_param2var:

						data = query[k][0]
						for c in multiplexorproxyurl_param2var[k[5:]][1]:
							data = c(data)

						setattr(
							res, 
							multiplexorproxyurl_param2var[k[5:]][0], 
							data
						)
		res.sanity_check()

		return res

def stru(x):
	return str(x).upper()

multiplexorproxyurl_param2var = {
	'type' : ('version', [stru, MSLDAPProxyType]),
	'host' : ('ip', [str]),
	'port' : ('port', [int]),
	'timeout': ('timeout', [int]),
	'user' : ('username', [str]),
	'pass' : ('password', [str]),
	#'authtype' : ('authtype', [SOCKS5Method]),
	'agentid' : ('agent_id', [str]),
	'domain' : ('domain', [str])

}

