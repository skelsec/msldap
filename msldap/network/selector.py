
from msldap import logger
from msldap.network.tcp import MSLDAPTCPNetwork
from msldap.network.socks import SocksProxyConnection
from msldap.network.multiplexor import MultiplexorProxyConnection
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
	async def select(target):
		if target.proxy is not None:
			if target.proxy.type in MSLDAP_SOCKS_PROXY_TYPES:
				return SocksProxyConnection(target)
			elif target.proxy.type == MSLDAPProxyType.WSNET:
				from msldap.network.wsnet import WSNetProxyConnection
				return WSNetProxyConnection(target)
			else:
				mpc = MultiplexorProxyConnection(target)
				socks_proxy = await mpc.connect()
				return socks_proxy

		return MSLDAPTCPNetwork(target)