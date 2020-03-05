import copy
import asyncio

from msldap.commons.proxy import MSLDAPProxyType


class Proxyhandler:
	def __init__(self, target):
		self.target = target
	
	def select(self):
		if self.target.proxy is None:
			return self.target
		
		if self.target.proxy.proxy_type in [MSLDAPProxyType.SOCKS5, MSLDAPProxyType.SOCKS5_SSL]:
			import socket
			try:
				from socks5line.socks5line import Socks5LineProxyServer,SOCKS5Line 
			except ImportError:
				raise Exception('Failed to import socks5line proxy emulator! Install it then retry!')
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.bind(('127.0.0.1', 0))
			new_port = s.getsockname()[1]
			proxy = Socks5LineProxyServer()
			proxy.ip = self.target.proxy.ip
			proxy.port = self.target.proxy.port
			proxy.timeout = self.target.proxy.timeout
			proxy.username = self.target.proxy.username
			proxy.password = self.target.proxy.secret

			sl = SOCKS5Line(proxy, self.target.host, self.target.port)
			sl.run_newthread(s)

			newtarget = copy.deepcopy(self.target)
			newtarget.proxy = None
			newtarget.host = '127.0.0.1'
			newtarget.port = new_port

			return newtarget

		elif self.target.proxy.proxy_type in [LDAPProxyType.MULTIPLEXOR, LDAPProxyType.MULTIPLEXOR_SSL]:
			import socket
			try:
				from socks5line.socks5line import Socks5LineProxyServer,SOCKS5Line 
			except ImportError:
				raise Exception('Failed to import socks5line proxy emulator! Install it then retry!')
			try:
				from multiplexor.operator import MultiplexorOperator
			except ImportError:
				raise Exception('Failed to import multiplexor! Install it then retry!')

			async def create_proxy(connection_string, agent_id):
				try:
					#creating operator and connecting to multiplexor server
					self.operator = MultiplexorOperator(con_str, reconnect_tries = 1)
					await self.operator.connect()
					#creating socks5 proxy
					server_info = await self.operator.start_socks5(agent_id)
					asyncio.create_task(self.operator.terminate())
					return server_info
				except Exception as e:
					asyncio.create_task(self.operator.terminate())
					return e

			#creating connection string
			if self.target.proxy.proxy_type == LDAPProxyType.MULTIPLEXOR:
				con_str = 'ws://%s:%s' % (self.target.proxy.ip, self.target.proxy.port)
			else:
				con_str = 'wss://%s:%s' % (self.target.proxy.ip, self.target.proxy.port)
			

			#because of URL stuff, this logic needs to be in place
			#if self.target.proxy.domain is None:
			#	agent_id = self.target.proxy.username
			#else:
			#	agent_id = self.target.proxy.domain
			print('proxy_connecting')
			server_info = asyncio.run(create_proxy(con_str, self.target.proxy.settings['agentid'][0]))
			print('socks5 server info %s' % server_info)
			if isinstance(server_info, Exception):
				raise Exception('Failed to create socks proxy Reason: %s '% server_info)
			#copying the original target, then feeding it to socks5proxy object. it will hold the actual socks5 proxy server address we created before
			
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.bind(('127.0.0.1', 0))
			new_port = s.getsockname()[1]
			proxy = Socks5LineProxyServer()
			proxy.ip = server_info['listen_ip']
			proxy.port = server_info['listen_port']
			proxy.timeout = self.target.proxy.timeout
			proxy.username = self.target.proxy.username
			proxy.password = self.target.proxy.secret

			sl = SOCKS5Line(proxy, self.target.host, self.target.port)
			sl.run_newthread(s)
			
			print('socks5 socks5line ready')
			newtarget = copy.deepcopy(self.target)
			newtarget.proxy = None
			newtarget.host = '127.0.0.1'
			newtarget.port = new_port

			return newtarget