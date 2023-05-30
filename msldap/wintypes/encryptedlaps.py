import io
import enum
from asn1crypto.cms import ContentInfo

class EncryptedLAPSBlob:
	def __init__(self):
		self.update_timestamp: int
		self.flags: int
		self.blob: bytes
		self.asn1blob: ContentInfo
	
	def get_keyidentifier(self):
		sid = self.asn1blob.native['content']['recipient_infos'][0]['kekid']['other']['key_attr']['1']['0']['0']['1']
		print(sid)
		return LAPS_KEYIDENTIFIER.from_bytes(self.asn1blob.native['content']['recipient_infos'][0]['kekid']['key_identifier'])
	
	def from_bytes(data: bytes):
		return EncryptedLAPSBlob.from_buffer(io.BytesIO(data))
	
	def from_buffer(buff: io.BytesIO):
		blob = EncryptedLAPSBlob()
		blob.update_timestamp = int.from_bytes(buff.read(8), byteorder='little', signed=False)
		blob_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.flags = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.blob = buff.read(blob_length)
		blob.asn1blob = ContentInfo.load(blob.blob)
		return blob
	
	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s: %s\n' % (k, self.__dict__[k])
		return t

class KEYIDFLAGS(enum.IntFlag):
	DHPARAMS = 1
	UNKNOWN = 2

	
class LAPS_KEYIDENTIFIER:
	def __init__(self):
		self.version = None
		self.magic = None
		self.flags = None
		self.l0_index = None
		self.l1_index = None
		self.l2_index = None
		self.root_key_identifier = None
		self.unknown_length = None
		self.domain_length = None
		self.forest_length = None
		self.unknown = None
		self.domain = None
		self.forest = None
	
	@staticmethod
	def from_bytes(data:bytes):
		return LAPS_KEYIDENTIFIER.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		blob = LAPS_KEYIDENTIFIER()
		blob.version = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.magic = buff.read(4)
		blob.flags = KEYIDFLAGS(int.from_bytes(buff.read(4), byteorder='little', signed=False))
		blob.l0_index = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.l1_index = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.l2_index = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.root_key_identifier = buff.read(16)
		blob.unknown_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.domain_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.forest_length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		blob.unknown = buff.read(blob.unknown_length)
		blob.domain = buff.read(blob.domain_length)
		blob.forest = buff.read(blob.forest_length)
		return blob
	
	def __str__(self):
		t = ''
		for k in self.__dict__:
			if isinstance(self.__dict__[k], bytes):
				t += '%s: %s\n' % (k, self.__dict__[k].hex())
			else:
				t += '%s: %s\n' % (k, self.__dict__[k])
		return t