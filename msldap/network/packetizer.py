import asyncio

from msldap import logger
from msldap.protocol.utils import calcualte_length
from asysocks.unicomm.common.packetizers import Packetizer

class LDAPPacketizer(Packetizer):
	def __init__(self):
		Packetizer.__init__(self, 65535)
		self.in_buffer = b''
		self.is_plain_msg = True
	
	def process_buffer(self):
		preread = 6
		remaining_length = -1
		while True:
			if len(self.in_buffer) < preread:
				break
			lb = self.in_buffer[:preread]
			if self.is_plain_msg is True:
				remaining_length = calcualte_length(lb) - preread
			else:
				remaining_length = int.from_bytes(lb[:4], byteorder = 'big', signed = False)
				remaining_length = (remaining_length + 4) - preread
			if len(self.in_buffer) >= remaining_length+preread:
				data = self.in_buffer[:remaining_length+preread]
				self.in_buffer = self.in_buffer[remaining_length+preread:]
				yield data
				continue
			break
		

	async def data_out(self, data):
		yield data

	async def data_in(self, data):
		if data is None:
			yield data
		self.in_buffer += data
		for packet in self.process_buffer():
			yield packet