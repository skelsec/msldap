import enum
import io
import collections

class MsvAvFlags(enum.IntFlag):
	CONSTRAINED_AUTH = 0x00000001
	MIC_PRESENT      = 0x00000002
	SPN_UNTRUSTED    = 0x00000004

class AVPAIRType(enum.Enum):
	MsvAvEOL             = 0x0000 #Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
	MsvAvNbComputerName  = 0x0001 #The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
	MsvAvNbDomainName    = 0x0002 #The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
	MsvAvDnsComputerName = 0x0003 #The fully qualified domain name (FQDN) of the computer. The name MUST be in Unicode, and is not null-terminated.
	MsvAvDnsDomainName   = 0x0004 #The FQDN of the domain. The name MUST be in Unicode, and is not null-terminated.
	MsvAvDnsTreeName     = 0x0005 #The FQDN of the forest. The name MUST be in Unicode, and is not null-terminated.<13>
	MsvAvFlags           = 0x0006 #A 32-bit value indicating server or client configuration.
	MsvAvTimestamp       = 0x0007 #A FILETIME structure ([MS-DTYP] section 2.3.3) in little-endian byte order that contains the server local time. This structure is always sent in the CHALLENGE_MESSAGE.<16>
	MsvAvSingleHost      = 0x0008 #A Single_Host_Data (section 2.2.2.2) structure. The Value field contains a platform-specific blob, as well as a MachineID created at computer startup to identify the calling machine.<17>
	MsvAvTargetName      = 0x0009 #The SPN of the target server. The name MUST be in Unicode and is not null-terminated.<18>
	MsvChannelBindings   = 0x000A #A channel bindings hash. The Value field contains an MD5 hash ([RFC4121] section 4.1.1.2) of a gss_channel_bindings_struct ([RFC2744] section 3.11). An all-zero value of the hash is used to indicate absence of channel bindings.<19>


# ???? https://msdn.microsoft.com/en-us/library/windows/desktop/aa374793(v=vs.85).aspx
# https://msdn.microsoft.com/en-us/library/cc236646.aspx
class AVPairs(collections.UserDict):
	"""
	AVPairs is a dictionary-like object that stores the "AVPair list" in a key -value format where key is an AVPAIRType object and value is the corresponding object defined by the MSDN documentation. Usually it's string but can be other object as well
	"""
	def __init__(self, data = None):
		collections.UserDict.__init__(self, data)

	@staticmethod
	def from_bytes(bbuff):
		return AVPairs.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		avp = AVPairs()
		while True:
			avId  = AVPAIRType(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
			AvLen = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
			if avId == AVPAIRType.MsvAvEOL:
				break

			elif avId in [AVPAIRType.MsvAvNbComputerName,
						  AVPAIRType.MsvAvNbDomainName,
						  AVPAIRType.MsvAvDnsComputerName,
						  AVPAIRType.MsvAvDnsDomainName,
						  AVPAIRType.MsvAvDnsTreeName,
						  AVPAIRType.MsvAvTargetName,
			]:
				avp[avId] = buff.read(AvLen).decode('utf-16le')
				
			elif avId == AVPAIRType.MsvAvFlags:
				avp[avId] = MsvAvFlags(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))

			# TODO IMPLEMENT PARSING OFR OTHER TYPES!!!!
			else:
				avp[avId] = buff.read(AvLen)

		return avp

	def to_bytes(self):
		t = b''
		for av in self.data:
			t += AVPair(data = self.data[av], type = av).to_bytes()

		t += AVPair(data = '', type = AVPAIRType.MsvAvEOL).to_bytes()
		return t


class AVPair:
	def __init__(self, data = None, type = None):
		self.type = type
		self.data = data

	def to_bytes(self):
		t  = self.type.value.to_bytes(2, byteorder = 'little', signed = False)
		raw_data = None
		if self.type in [AVPAIRType.MsvAvNbComputerName,
						  AVPAIRType.MsvAvNbDomainName,
						  AVPAIRType.MsvAvDnsComputerName,
						  AVPAIRType.MsvAvDnsDomainName,
						  AVPAIRType.MsvAvDnsTreeName,
						  AVPAIRType.MsvAvTargetName,
						  AVPAIRType.MsvAvEOL
			]:
			raw_data = self.data.encode('utf-16le')
		else:
			raw_data = self.data
		t += len(raw_data).to_bytes(2, byteorder = 'little', signed = False)
		t += raw_data
		return t


