
from asn1crypto.x509 import Certificate

MSADCA_ATTRS = ['cACertificate', 'cn', 'sn', 'distinguishedName', 'whenChanged', 'whenCreated', 'name']

class MSADCA:
	def __init__(self):
		self.location = None
		self.sn = None #str
		self.cn = None #str
		self.distinguishedName = None #dn
		self.whenChanged = None
		self.whenCreated = None
		self.cACertificate = None
		self.name = None
		
	@staticmethod
	def from_ldap(entry, location):
		adi = MSADCA()
		adi.location = location
		adi.sn = entry['attributes'].get('sn') 
		adi.cn = entry['attributes'].get('cn') 
		adi.distinguishedName = entry['attributes'].get('distinguishedName')
		adi.whenChanged = entry['attributes'].get('whenChanged')
		adi.whenCreated = entry['attributes'].get('whenCreated')
		adi.cACertificate = entry['attributes'].get('cACertificate')
		if adi.cACertificate is not None:
			adi.cACertificate = Certificate.load(adi.cACertificate)
		adi.name = entry['attributes'].get('name')

		return adi		
		
	def __str__(self):
		t = '== MSADCA ==\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])

		return t
