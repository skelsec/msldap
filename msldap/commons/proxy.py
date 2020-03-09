
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

class MSLDAPProxy:
	def __init__(self):
		self.type = None
		self.target = None
		self.auth   = None


	@staticmethod
	def from_params(url_str):
		proxy = MSLDAPProxy()
		url = urlparse(url_str)
		if url.query is None:
			return None

		query = parse_qs(url.query)
		if 'proxytype' not in query and 'sametype' not in query:
			return None
		
		proxy.type = MSLDAPProxyType(query['proxytype'][0].upper())
		if proxy.type in [MSLDAPProxyType.SOCKS4, MSLDAPProxyType.SOCKS4_SSL, MSLDAPProxyType.SOCKS5, MSLDAPProxyType.SOCKS5_SSL]:
			cu = SocksClientURL.from_params(url_str)
		else:
			raise Exception('Multiplexor not yet implemented as a proxy!')
			#cu = SocksClientURL.from_params(url_str)
		
		proxy.target = cu.get_target()
		proxy.auth = cu.get_creds()
		return proxy

	def __str__(self):
		t = '==== MSLDAPProxy ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
	
		


