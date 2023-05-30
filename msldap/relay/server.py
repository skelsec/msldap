from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.server import UniServer
from msldap.network.packetizer import LDAPPacketizer
from msldap.relay.serverconnection import LDAPRelayServerConnection
from asyauth.protocols.spnego.relay.native import spnegorelay_ntlm_factory
from asyauth.protocols.ntlm.relay.native import NTLMRelaySettings, ntlmrelay_factory
import traceback
import asyncio

class LDAPServerSettings:
	def __init__(self, gssapi_factory):
		self.gssapi_factory = gssapi_factory
	
	@property
	def gssapi(self):
		return self.gssapi_factory()
	
class LDAPRelayServer:
	def __init__(self, target, settings):
		self.target = target
		self.settings = settings
		self.server = None
		self.serving_task = None
		self.connections = {}
		self.conn_ctr = 0
		
	def get_ctr(self):
		self.conn_ctr += 1
		return self.conn_ctr

	async def __handle_connection(self):
		try:
			async for connection in self.server.serve():
				print('connection in!')
				
				smbconnection = LDAPRelayServerConnection(self.settings, connection)
				self.connections[self.get_ctr()] = smbconnection
				x = asyncio.create_task(smbconnection.run())

		except Exception as e:
			traceback.print_exc()
			return

	async def run(self):
		self.server = UniServer(self.target, LDAPPacketizer())
		self.serving_task = asyncio.create_task(self.__handle_connection())
		return self.serving_task

async def test_relay_queue(rq):
	try:
		from aiosmb.connection import SMBConnection
		from aiosmb.commons.connection.target import SMBTarget
		from aiosmb.commons.interfaces.machine import SMBMachine
		test_target = SMBTarget('10.10.10.2')
		while True:
			item = await rq.get()
			print(item)
			connection = SMBConnection(item, test_target, preserve_gssapi=False, nosign=True)
			_, err = await connection.login()
			if err is not None:
				print('SMB client login err: %s' % err)
				print(traceback.format_tb(err.__traceback__))
				continue
			machine = SMBMachine(connection)
			async for share, err in machine.list_shares():
				if err is not None:
					print('SMB client list_shares err: %s' % err)
					continue
				print(share)

	except Exception as e:
		traceback.print_exc()
		return

async def amain():
	try:
		auth_relay_queue = asyncio.Queue()
		x = asyncio.create_task(test_relay_queue(auth_relay_queue))
		target = UniTarget('0.0.0.0', 636, UniProto.SERVER_SSL_TCP)

		settings = LDAPServerSettings(lambda: spnegorelay_ntlm_factory(auth_relay_queue, lambda: ntlmrelay_factory()))
		server = LDAPRelayServer(target, settings)
		server_task = await server.run()
		await server_task
	except Exception as e:
		traceback.print_exc()
		return
if __name__ == '__main__':
	asyncio.run(amain())