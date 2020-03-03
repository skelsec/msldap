import io

class NTLMSSP_MESSAGE_SIGNATURE_NOEXT:
	def __init__(self):
		self.Version = 1
		self.RandomPad = None
		self.Checksum = None
		self.SeqNum = None

	def to_bytes(self):
		t = self.Version.to_bytes(4, byteorder = 'little', signed = False)
		t += self.RandomPad
		t += self.Checksum
		t += self.SeqNum.to_bytes(4, byteorder = 'little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return NTLMSSP_MESSAGE_SIGNATURE_NOEXT.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		v = NTLMSSP_MESSAGE_SIGNATURE_NOEXT()
		v.Version = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		v.RandomPad = buff.read(4)
		v.Checksum = buff.read(4)
		v.SeqNum = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
			
		return v

	def __repr__(self):
		t  = '== NTLMSSP_MESSAGE_SIGNATURE_NOEXT ==\r\n'
		t += 'Version  : %s\r\n' % self.Version
		t += 'RandomPad  : %s\r\n' % self.RandomPad
		t += 'Checksum  : %s\r\n' % self.Checksum
		t += 'SeqNum  : %s\r\n' % self.SeqNum
		return t