
import enum
import asyncio
import ipaddress

from msldap import logger

from asysocks.client import SOCKSClient
from asysocks.common.comms import SocksQueueComms
from msldap.protocol.utils import calcualte_length


class SocksProxyConnection:
	"""
	Generic asynchronous TCP socket class, nothing SMB related.
	Creates the connection and channels incoming/outgoing bytes via asynchonous queues.
	"""
	def __init__(self, target):
		self.target = target
		
		self.client = None
		self.proxy_task = None
		self.handle_in_task = None

		self.out_queue = None#asyncio.Queue()
		self.in_queue = None#asyncio.Queue()

		self.proxy_in_queue = None#asyncio.Queue()
		self.is_plain_msg = True
		
	async def disconnect(self):
		"""
		Disconnects from the socket.
		Stops the reader and writer streams.
		"""
		if self.client is not None:
			await self.client.terminate()
		if self.proxy_task is not None:
			self.proxy_task.cancel()
		if self.handle_in_q is not None:
			self.handle_in_task.cancel()

	async def terminate(self):
		await self.disconnect()

	def get_peer_certificate(self):
		raise Exception('Not yet implemented! SSL implementation on socks is missing!')
		return self.writer.get_extra_info('socket').getpeercert(True)

	def get_one_message(self,data):
		if len(data) < 6:
			return None

		if self.is_plain_msg is True:
			dl = calcualte_length(data[:6])
		else:
			dl = int.from_bytes(data[:4], byteorder = 'big', signed = False)
			dl = dl + 4

		
		#print(dl)
		if len(data) >= dl:
			return data[:dl]
			
	async def handle_in_q(self):
		try:
			data = b''
			while True:
				while True:
					msg_data = self.get_one_message(data)
					if msg_data is None:
						break

					await self.in_queue.put((msg_data, None))
					data = data[len(msg_data):]
				
				temp, err = await self.proxy_in_queue.get()
				#print(temp)
				if err is not None:
					raise err

				if temp == b'' or temp is None:
					logger.debug('Server finished!')
					return

				data += temp
				continue
		
		except asyncio.CancelledError:
			return
		except Exception as e:
			logger.exception('handle_in_q')
			await self.in_queue.put((None, e))

		finally:
			self.proxy_task.cancel()


		
	async def run(self):
		"""
		
		"""
		try:
			self.out_queue = asyncio.Queue()
			self.in_queue = asyncio.Queue()

			self.proxy_in_queue = asyncio.Queue()
			comms = SocksQueueComms(self.out_queue, self.proxy_in_queue)

			self.target.proxy.target[-1].endpoint_ip = self.target.host if self.target.serverip is None else self.target.serverip
			self.target.proxy.target[-1].endpoint_port = int(self.target.port)
			self.target.proxy.target[-1].endpoint_timeout = None #TODO: maybe implement endpoint timeout?
			self.target.proxy.target[-1].timeout = self.target.timeout
			self.client = SOCKSClient(comms, self.target.proxy.target)
			self.proxy_task = asyncio.create_task(self.client.run())
			self.handle_in_task = asyncio.create_task(self.handle_in_q())
			return True, None
		except Exception as e:
			return False, e

