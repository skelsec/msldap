# parts of the dns implementation was taken from https://github.com/dirkjanm/adidnsdump

import datetime
import enum
import io
from typing import List

from msldap.commons.utils import bytes2ipv4, bytes2ipv6


class DNS_RECORD_TYPE(enum.Enum):
	ZERO = 0x0000 #An empty record type ([RFC1034] section 3.6 and [RFC1035] section 3.2.2).
	A = 0x0001 #An A record type, used for storing an IP address ([RFC1035] section 3.2.2).
	NS = 0x0002 #An authoritative name-server record type ([RFC1034] section 3.6 and [RFC1035] section 3.2.2).
	MD = 0x0003 #A mail-destination record type ([RFC1035] section 3.2.2).
	MF = 0x0004 #A mail forwarder record type ([RFC1035] section 3.2.2).
	CNAME = 0x0005 #A record type that contains the canonical name of a DNS alias ([RFC1035] section 3.2.2).
	SOA = 0x0006 #A Start of Authority (SOA) record type ([RFC1035] section 3.2.2).
	MB = 0x0007 #A mailbox record type ([RFC1035] section 3.2.2).
	MG = 0x0008 #A mail group member record type ([RFC1035] section 3.2.2).
	MR = 0x0009 #A mail-rename record type ([RFC1035] section 3.2.2).
	NULL = 0x000A #A record type for completion queries ([RFC1035] section 3.2.2).
	WKS = 0x000B #A record type for a well-known service ([RFC1035] section 3.2.2).
	PTR = 0x000C #A record type containing FQDN pointer ([RFC1035] section 3.2.2).
	HINFO = 0x000D #A host information record type ([RFC1035] section 3.2.2).
	MINFO = 0x000E #A mailbox or mailing list information record type ([RFC1035] section 3.2.2).
	MX = 0x000F #A mail-exchanger record type ([RFC1035] section 3.2.2).
	TXT = 0x0010 #A record type containing a text string ([RFC1035] section 3.2.2).
	RP = 0x0011 #A responsible-person record type [RFC1183].
	AFSDB = 0x0012 #A record type containing AFS database location [RFC1183].
	X25 = 0x0013 #An X25 PSDN address record type [RFC1183].
	ISDN = 0x0014 #An ISDN address record type [RFC1183].
	RT = 0x0015 #A route through record type [RFC1183].
	SIG = 0x0018 #A cryptographic public key signature record type [RFC2931].
	KEY = 0x0019 #A record type containing public key used in DNSSEC [RFC2535].
	AAAA = 0x001C #An IPv6 address record type [RFC3596].
	LOC = 0x001D #A location information record type [RFC1876].
	NXT = 0x001E #A next-domain record type [RFC2065].
	SRV = 0x0021 #A server selection record type [RFC2782].
	ATMA = 0x0022 # An Asynchronous Transfer Mode (ATM) address record type [ATMA].
	NAPTR = 0x0023 #An NAPTR record ype [RFC2915].
	DNAME = 0x0027 #A DNAME record type [RFC2672].
	DS = 0x002B #A DS record type [RFC4034].
	RRSIG = 0x002E #An RRSIG record type [RFC4034].
	NSEC = 0x002F #An NSEC record type [RFC4034].
	DNSKEY = 0x0030 #A DNSKEY record type [RFC4034].
	DHCID = 0x0031 #A DHCID record type [RFC4701]. 
	NSEC3 = 0x0032 #An NSEC3 record type [RFC5155].
	NSEC3PARAM = 0x0033 #An NSEC3PARAM record type [RFC5155].
	TLSA = 0x0034 #A TLSA record type [RFC6698].
	ALL = 0x00FF #A query-only type requesting all records [RFC1035].
	WINS = 0xFF01 # A record type containing Windows Internet Name Service (WINS) forward lookup data [MS-WINSRA].
	WINSR = 0xFF02 #A record type containing WINS reverse lookup data [MS-WINSRA].


# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/ac793981-1c60-43b8-be59-cdbb5c4ecb8a
class DNS_RECORD:
	def __init__(self):
		self.DataLength:int = None
		self.Type:DNS_RECORD_TYPE = None
		self.Version: bytes = b'\x05'
		self.Rank:bytes = None
		self.Flags:bytes = b'\x00\x00'
		self.Serial:bytes = None
		self.TtlSeconds:int = None
		self.Reserved:bytes = b'\x00\x00\x00\x00'
		self.TimeStamp:bytes = None
		self.Data:bytes = None
	
	@staticmethod
	def from_bytes(data):
		return DNS_RECORD.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		res = DNS_RECORD()
		res.DataLength = int.from_bytes(buff.read(2), 'little', signed = False)
		res.Type = DNS_RECORD_TYPE(int.from_bytes(buff.read(2), 'little', signed = False))
		res.Version = buff.read(1)
		res.Rank = buff.read(1)
		res.Flags = buff.read(2)
		res.Serial = buff.read(4)
		res.TtlSeconds = int.from_bytes(buff.read(4), 'little', signed = False)
		res.Reserved = buff.read(4)
		res.TimeStamp = buff.read(4)
		res.Data = buff.read(res.DataLength)
		return res
	
	def get_formatted(self):
		if self.Data is None or len(self.Data) == 0:
			return None
		if self.Type in MSLDAP_DNS_TYPE_TO_CLASS:
			return MSLDAP_DNS_TYPE_TO_CLASS[self.Type].from_bytes(self.Data)
		return DNS_RPC_RECORD_UNKNOWN.from_bytes(self.Data)
	
	def __str__(self):
		t = '==== DNS_RECORD ====\r\n'
		t += 'DataLength: %s\r\n' % self.DataLength
		t += 'Type: %s\r\n' % self.Type.name
		t += 'Version: %s\r\n' % self.Version.hex()
		t += 'Rank: %s\r\n' % self.Rank.hex()
		t += 'Flags: %s\r\n' % self.Flags.hex()
		t += 'Serial: %s\r\n' % self.Serial.hex()
		t += 'TtlSeconds: %s\r\n' % self.TtlSeconds
		t += 'Reserved: %s\r\n' % self.Reserved.hex()
		t += 'TimeStamp: %s\r\n' % self.TimeStamp.hex()
		t += 'Data: %s\r\n' % self.Data.hex()
		return t
	
class DNS_RPC_RECORD_UNKNOWN:
	def __init__(self):
		self.Data:bytes = None
	
	@staticmethod
	def from_bytes(data):
		return DNS_RPC_RECORD_UNKNOWN.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		res = DNS_RPC_RECORD_UNKNOWN()
		res.Data = buff.read()
		return res

	def to_line(self, separator = '\t'):
		return str(self)
	
	def __str__(self):
		return self.Data.hex()

class DNS_RPC_RECORD_A:
	def __init__(self):
		self.IpAddress:str = None
	
	@staticmethod
	def from_bytes(data):
		return DNS_RPC_RECORD_A.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		res = DNS_RPC_RECORD_A()
		#webassembly...
		#res.IpAddress = socket.inet_ntoa(buff.read(4))
		ipv4_bytes = buff.read(4)
		
		# Convert each byte to an integer and join them with dots to form the IPv4 address
		res.IpAddress = bytes2ipv4(ipv4_bytes)
		
		return res
	
	def to_line(self, separator = '\t'):
		return str(self)
	
	def __str__(self):
		return self.IpAddress

class DNS_RPC_RECORD_AAAA:
	def __init__(self):
		self.IpAddress:str = None
	
	@staticmethod
	def from_bytes(data):
		return DNS_RPC_RECORD_AAAA.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		res = DNS_RPC_RECORD_AAAA()
		# webassembly pyodide has problems with socket implementation
		#res.IpAddress = socket.inet_ntop(socket.AF_INET6, buff.read(16))
		ipv6_bytes = buff.read(16)

		# Convert the hex string into the standard IPv6 format
		res.IpAddress = bytes2ipv6(ipv6_bytes)
		return res
	
	def to_line(self, separator = '\t'):
		return str(self)
	
	def __str__(self):
		return self.IpAddress

class DNS_RPC_RECORD_SRV:
	def __init__(self):
		self.wPriority:int = None
		self.wWeight:int = None
		self.wPort:int = None
		self.nameTarget:DNS_COUNT_NAME = None
	
	@staticmethod
	def from_bytes(data):
		return DNS_RPC_RECORD_SRV.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		res = DNS_RPC_RECORD_SRV()
		res.wPriority = int.from_bytes(buff.read(2), 'little', signed = False)
		res.wWeight = int.from_bytes(buff.read(2), 'little', signed = False)
		res.wPort = int.from_bytes(buff.read(2), 'little', signed = False)
		res.nameTarget = DNS_COUNT_NAME.from_buffer(buff)
		return res
	
	def to_line(self, separator = '\t'):
		return separator.join([
			str(self.wPriority), 
			str(self.wWeight), 
			str(self.wPort), 
			str(self.nameTarget)
		])
	
	def __str__(self):
		return 'Prio: %s | Weight: %s | Port: %s | Name: %s' % (self.wPriority, self.wWeight, self.wPort, self.nameTarget)

class DNS_RPC_RECORD_TS:
	def __init__(self):
		self.entombedTime:datetime.datetime = None
	
	@staticmethod
	def from_bytes(data):
		return DNS_RPC_RECORD_TS.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		res = DNS_RPC_RECORD_TS()
		tsraw = buff.read(8, signed = False, byteorder = 'little')
		microseconds = tsraw / 10
		try:
			res.entombedTime = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)
		except OverflowError:
			return None
		return res
	
	def to_line(self, separator = '\t'):
		return str(self)
	
	def __str__(self):
		return str(self.entombedTime)

class DNS_COUNT_NAME:
	def __init__(self):
		self.Length:int = None
		self.LabelCount:int = None
		#self.RawName:str = None
		self.labels:List[str] = []
	
	@staticmethod
	def from_bytes(data):
		return DNS_COUNT_NAME.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		res = DNS_COUNT_NAME()
		res.Length = int.from_bytes(buff.read(1), 'little', signed = False)
		res.LabelCount = int.from_bytes(buff.read(1), 'little', signed = False)
		#res.RawName = buff.read(res.Length)
		for _ in range(res.LabelCount):
			res.labels.append(buff.read(buff.read(1)[0]).decode('utf-8'))
		buff.read(1) # IMPORTANT! The last byte is always 0x00 and is not indicated in the LabelCount
		return res
	
	def to_line(self, separator = '\t'):
		return str(self)
	
	def __str__(self):
		return '.'.join(self.labels)

class DNS_RPC_RECORD_NULL:
	def __init__(self):
		self.bData:bytes = b''
	
	@staticmethod
	def from_bytes(data):
		return DNS_RPC_RECORD_NULL.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		res = DNS_RPC_RECORD_NULL()
		return res
	
	def to_line(self, separator = '\t'):
		return ''
	
	def __str__(self):
		return ''


class DNS_RPC_RECORD_SOA:
	def __init__(self):
		self.dwSerialNo:int = None
		self.dwRefresh:int = None
		self.dwRetry:int = None
		self.dwExpire:int = None
		self.dwMinimumTtl:int = None
		self.namePrimaryServer:DNS_COUNT_NAME = None
		self.zoneAdminEmail:DNS_COUNT_NAME = None
	
	@staticmethod
	def from_bytes(data):
		return DNS_RPC_RECORD_SOA.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		res = DNS_RPC_RECORD_SOA()
		res.dwSerialNo = int.from_bytes(buff.read(4), 'little', signed = False)
		res.dwRefresh = int.from_bytes(buff.read(4), 'little', signed = False)
		res.dwRetry = int.from_bytes(buff.read(4), 'little', signed = False)
		res.dwExpire = int.from_bytes(buff.read(4), 'little', signed = False)
		res.dwMinimumTtl = int.from_bytes(buff.read(4), 'little', signed = False)
		res.namePrimaryServer = DNS_COUNT_NAME.from_buffer(buff)
		res.zoneAdminEmail = DNS_COUNT_NAME.from_buffer(buff)
		return res
	
	def to_line(self, separator = '\t'):
		return separator.join([
			str(self.dwSerialNo), 
			str(self.dwRefresh), 
			str(self.dwRetry), 
			str(self.dwExpire), 
			str(self.dwMinimumTtl),
			str(self.namePrimaryServer), 
			str(self.zoneAdminEmail)
		])
	
	def __str__(self):
		return 'Serial: %s | Refresh: %s | Retry: %s | Expire: %s | TTL: %s | NS: %s | Email: %s' % (self.dwSerialNo, self.dwRefresh, self.dwRetry, self.dwExpire, self.dwMinimumTtl, self.namePrimaryServer, self.zoneAdminEmail)



MSLDAP_DNS_TYPE_TO_CLASS = {
	DNS_RECORD_TYPE.ZERO : DNS_RPC_RECORD_NULL,
	DNS_RECORD_TYPE.A : DNS_RPC_RECORD_A,
	DNS_RECORD_TYPE.AAAA : DNS_RPC_RECORD_AAAA,
	DNS_RECORD_TYPE.SRV : DNS_RPC_RECORD_SRV,
	DNS_RECORD_TYPE.PTR : DNS_COUNT_NAME,
	DNS_RECORD_TYPE.NS : DNS_COUNT_NAME,
	DNS_RECORD_TYPE.CNAME : DNS_COUNT_NAME,
	DNS_RECORD_TYPE.DNAME : DNS_COUNT_NAME,
	DNS_RECORD_TYPE.MB : DNS_COUNT_NAME,
	DNS_RECORD_TYPE.MR : DNS_COUNT_NAME,
	DNS_RECORD_TYPE.MG : DNS_COUNT_NAME,
	DNS_RECORD_TYPE.MD : DNS_COUNT_NAME,
	DNS_RECORD_TYPE.MF : DNS_COUNT_NAME,
	DNS_RECORD_TYPE.SOA : DNS_RPC_RECORD_SOA,
}
