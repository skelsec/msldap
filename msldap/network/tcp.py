
import asyncio

from msldap import logger
from msldap.protocol.utils import calcualte_length

class MSLDAPTCPNetwork:
	def __init__(self, target):
		self.target = target
		self.timeout = None
		self.in_queue = None
		self.out_queue = None
		self.reader = None
		self.writer = None

		self.handle_in_task = None
		self.handle_out_task = None

		self.is_plain_msg = True

	async def terminate(self):
		self.handle_in_task.cancel()
		self.handle_out_task.cancel()
	
	def get_peer_certificate(self):
		return self.writer.get_extra_info('ssl_object').getpeercert(True)

	async def handle_in_q(self):
		try:
			while True:
				
				preread = 6
				lb = await asyncio.wait_for(self.reader.readexactly(preread), self.timeout)
				if lb is None:
					logger.debug('Server timed out!')
					return
				if lb == b'':
					logger.debug('Server finished!')
					return

				if self.is_plain_msg is True:
					remaining_length = calcualte_length(lb) - preread
				else:
					remaining_length = int.from_bytes(lb[:4], byteorder = 'big', signed = False)
					remaining_length = (remaining_length + 4) - preread
				#print('Reading %s' % remaining_length)

				remaining_data = await asyncio.wait_for(self.reader.readexactly(remaining_length), self.timeout)
				
				await self.in_queue.put((lb+remaining_data, None))
				
		
		#except asyncio.CancelledError:
		#	return
		except Exception as e:
			#logger.exception('handle_in_q')
			await self.in_queue.put((None, e))

		finally:
			self.handle_out_task.cancel()

	async def handle_out_q(self):
		try:
			while True:
				data = await self.out_queue.get()
				if data is None:
					logger.debug('Client finished!')
					return

				self.writer.write(data)
				await self.writer.drain()
		except asyncio.CancelledError:
			return
		except:
			logger.exception('handle_out_q')
		
		finally:
			self.writer.close()
			self.handle_in_task.cancel()
			

	async def run(self):
		try:
			self.in_queue = asyncio.Queue()
			self.out_queue = asyncio.Queue()
			self.reader, self.writer = await asyncio.wait_for(
				asyncio.open_connection(
					self.target.serverip if self.target.serverip is not None else self.target.host, 
					self.target.port, 
					ssl=self.target.get_ssl_context()
					),
				timeout = self.target.timeout
			)

			self.handle_in_task = asyncio.create_task(self.handle_in_q())
			self.handle_out_task = asyncio.create_task(self.handle_out_q())
			return True, None
		except Exception as e:
			return False, e