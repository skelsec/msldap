import enum
import io

class NTLMRevisionCurrent(enum.Enum):
	NTLMSSP_REVISION_W2K3 = 0x0F


# https://msdn.microsoft.com/en-us/library/cc236722.aspx#Appendix_A_33
class WindowsMajorVersion(enum.Enum):
	WINDOWS_MAJOR_VERSION_5  = 0x05
	WINDOWS_MAJOR_VERSION_6  = 0x06
	WINDOWS_MAJOR_VERSION_10 = 0x0A


# https://msdn.microsoft.com/en-us/library/cc236722.aspx#Appendix_A_33
class WindowsMinorVersion(enum.Enum):
	WINDOWS_MINOR_VERSION_0 = 0x00
	WINDOWS_MINOR_VERSION_1 = 0x01
	WINDOWS_MINOR_VERSION_2 = 0x02
	WINDOWS_MINOR_VERSION_3 = 0x03

# https://msdn.microsoft.com/en-us/library/cc236722.aspx#Appendix_A_33
WindowsProduct = {
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_5, WindowsMinorVersion.WINDOWS_MINOR_VERSION_1) : 'Windows XP operating system Service Pack 2 (SP2)',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_5, WindowsMinorVersion.WINDOWS_MINOR_VERSION_2) : 'Windows Server 2003',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_6, WindowsMinorVersion.WINDOWS_MINOR_VERSION_0) : 'Windows Vista or Windows Server 2008',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_6, WindowsMinorVersion.WINDOWS_MINOR_VERSION_1) : 'Windows 7 or Windows Server 2008 R2',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_6, WindowsMinorVersion.WINDOWS_MINOR_VERSION_2) : 'Windows 8 or Windows Server 2012 operating system',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_6, WindowsMinorVersion.WINDOWS_MINOR_VERSION_3) : 'Windows 8.1 or Windows Server 2012 R2',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_10,WindowsMinorVersion.WINDOWS_MINOR_VERSION_0) : 'Windows 10 or Windows Server 2016',
}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175
class Version:
	def __init__(self):
		self.ProductMajorVersion = None
		self.ProductMinorVersion = None
		self.ProductBuild        = None
		self.Reserved            = 0
		self.NTLMRevisionCurrent = None

		# higher level
		self.WindowsProduct = None
		
	@staticmethod
	def construct(major = WindowsMajorVersion.WINDOWS_MAJOR_VERSION_10, minor = WindowsMinorVersion.WINDOWS_MINOR_VERSION_0, build = 1555 ):
		v = Version()
		v.ProductMajorVersion = major
		v.ProductMinorVersion = minor
		v.ProductBuild = build
		v.NTLMRevisionCurrent = NTLMRevisionCurrent.NTLMSSP_REVISION_W2K3
		
		return v

	def to_bytes(self):
		t = self.ProductMajorVersion.value.to_bytes(1, byteorder = 'little', signed = False)
		t += self.ProductMinorVersion.value.to_bytes(1, byteorder = 'little', signed = False)
		t += self.ProductBuild.to_bytes(2, byteorder = 'little', signed = False)
		t += self.Reserved.to_bytes(3, byteorder = 'little', signed = False)
		t += self.NTLMRevisionCurrent.value.to_bytes(1, byteorder = 'little', signed = False)
		return t

	@staticmethod
	def from_bytes(bbuff):
		return Version.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		v = Version()
		v.ProductMajorVersion = WindowsMajorVersion(int.from_bytes(buff.read(1), byteorder = 'little', signed = False))
		v.ProductMinorVersion = WindowsMinorVersion(int.from_bytes(buff.read(1), byteorder = 'little', signed = False))
		v.ProductBuild        = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		v.Reserved            = int.from_bytes(buff.read(3), byteorder = 'little', signed = False)
		v.NTLMRevisionCurrent = NTLMRevisionCurrent(int.from_bytes(buff.read(1), byteorder = 'little', signed = False))

		try:
			v.WindowsProduct = WindowsProduct[(v.ProductMajorVersion, v.ProductMinorVersion)]
		except:
			pass
			
		return v

	def __repr__(self):
		t  = '== NTLMVersion ==\r\n'
		t += 'ProductMajorVersion  : %s\r\n' % repr(self.ProductMajorVersion.name)
		t += 'ProductMinorVersion  : %s\r\n' % repr(self.ProductMinorVersion.name)
		t += 'ProductBuild         : %s\r\n' % repr(self.ProductBuild)
		t += 'WindowsProduct       : %s\r\n' % repr(self.WindowsProduct)
		return t