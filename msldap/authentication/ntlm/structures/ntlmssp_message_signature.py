import io

class NTLMSSP_MESSAGE_SIGNATURE:
	def __init__(self):
		self.Version = 1
		self.Checksum = None
		self.SeqNum = None

	def to_bytes(self):
		t = self.Version.to_bytes(4, byteorder = 'little', signed = False)
		t += self.Checksum
		t += self.SeqNum.to_bytes(4, byteorder = 'little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return NTLMSSP_MESSAGE_SIGNATURE.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		v = NTLMSSP_MESSAGE_SIGNATURE()
		v.Version = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		v.Checksum = buff.read(8)
		v.SeqNum = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
			
		return v

	def __repr__(self):
		t  = '== NTLMSSP_MESSAGE_SIGNATURE ==\r\n'
		t += 'Version  : %s\r\n' % self.Version
		t += 'Checksum  : %s\r\n' % self.Checksum
		t += 'SeqNum  : %s\r\n' % self.SeqNum
		return t