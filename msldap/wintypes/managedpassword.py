import io
from unicrypto.hashlib import md4

class MSDS_MANAGEDPASSWORD_BLOB:
	def __init__(self):
		self.Version = None
		self.Reserved = None
		self.Length = None
		self.CurrentPasswordOffset = None
		self.PreviousPasswordOffset = None
		self.QueryPasswordIntervalOffset = None
		self.UnchangedPasswordIntervalOffset = None
		self.CurrentPassword = None
		self.PreviousPassword = None
		#('AlignmentPadding',':'),
		self.QueryPasswordInterval = None
		self.UnchangedPasswordInterval = None

		self.nt_hash = None

	@staticmethod
	def from_bytes(data:bytes):
		return MSDS_MANAGEDPASSWORD_BLOB.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff:io.BytesIO):
		blob = MSDS_MANAGEDPASSWORD_BLOB()
		blob.Version = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		blob.Reserved = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		blob.Length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.CurrentPasswordOffset = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		blob.PreviousPasswordOffset = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		blob.QueryPasswordIntervalOffset = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		blob.UnchangedPasswordIntervalOffset = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		
		ppwo = blob.PreviousPasswordOffset
		if ppwo == 0:
			ppwo = blob.QueryPasswordIntervalOffset
		if blob.CurrentPasswordOffset >0:
			buff.seek(blob.CurrentPasswordOffset, 0)
			blob.CurrentPassword = buff.read(ppwo - blob.CurrentPasswordOffset)
		if blob.PreviousPasswordOffset >0:
			buff.seek(blob.PreviousPasswordOffset, 0)
			blob.PreviousPassword = buff.read(blob.QueryPasswordIntervalOffset - blob.CurrentPasswordOffset)
		if blob.QueryPasswordIntervalOffset >0:
			buff.seek(blob.QueryPasswordIntervalOffset, 0)
			blob.QueryPasswordInterval = buff.read(blob.UnchangedPasswordIntervalOffset - blob.UnchangedPasswordIntervalOffset)
		if blob.UnchangedPasswordIntervalOffset >0:
			buff.seek(blob.UnchangedPasswordIntervalOffset, 0)
			blob.UnchangedPasswordInterval = buff.read()


		blob.nt_hash = md4(blob.CurrentPassword[:-2]).hexdigest()		
		return blob
	
	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
		return t