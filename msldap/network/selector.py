
from msldap.network.tcp import MSLDAPTCPNetwork
from msldap.network.socks import SocksProxyConnection
from msldap.commons.proxy import MSLDAPProxyType

MSLDAP_SOCKS_PROXY_TYPES = [
				MSLDAPProxyType.SOCKS4 , 
				MSLDAPProxyType.SOCKS4_SSL , 
				MSLDAPProxyType.SOCKS5 , 
				MSLDAPProxyType.SOCKS5_SSL]

class MSLDAPNetworkSelector:
	def __init__(self):
		pass
	
	@staticmethod
	def select(target):
		if target.proxy is not None:
			if target.proxy.type in MSLDAP_SOCKS_PROXY_TYPES:
				return SocksProxyConnection(target)
			else:
				raise Exception('Multiplexor coming soon!')

		return MSLDAPTCPNetwork(target)