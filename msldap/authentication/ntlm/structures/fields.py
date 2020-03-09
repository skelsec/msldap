
class Fields:
	def __init__(self, length, offset, maxLength = None):
		self.length = length
		self.maxLength = length if maxLength is None else maxLength
		self.offset = offset

	@staticmethod
	def from_bytes(bbuff):
		return Fields.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer( buff):
		length    = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		maxLength = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		offset    = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)

		return Fields(length, offset, maxLength = maxLength)

	def to_bytes(self):
		return  self.length.to_bytes(2, byteorder = 'little', signed = False) + \
				self.maxLength.to_bytes(2, byteorder = 'little', signed = False) + \
				self.offset.to_bytes(4, byteorder = 'little', signed = False)