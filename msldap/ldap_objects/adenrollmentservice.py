

from msldap.commons.utils import print_cert
from asn1crypto.x509 import Certificate

MSADEnrollmentService_ATTRS = ['cACertificate', 'msPKI-Enrollment-Servers', 'dNSHostName', 'cn', 'sn', 'distinguishedName', 'whenChanged', 'whenCreated', 'name', 'displayName', 'cACertificateDN', 'certificateTemplates']

class MSADEnrollmentService:
	def __init__(self):
		self.sn = None #str
		self.cn = None #str
		self.distinguishedName = None #dn
		self.name = None
		self.displayName = None
		self.cACertificate = None
		self.cACertificateDN = None
		self.dNSHostName = None
		self.certificateTemplates = []
		self.enrollmentServers = []
		
	@staticmethod
	def from_ldap(entry):
		adi = MSADEnrollmentService()
		adi.sn = entry['attributes'].get('sn') 
		adi.cn = entry['attributes'].get('cn') 
		adi.distinguishedName = entry['attributes'].get('distinguishedName')
		adi.cACertificate = entry['attributes'].get('cACertificate')
		if adi.cACertificate is not None:
			adi.cACertificate = Certificate.load(adi.cACertificate)
		adi.name = entry['attributes'].get('name')
		adi.displayName = entry['attributes'].get('displayName')
		adi.dNSHostName = entry['attributes'].get('dNSHostName')
		adi.cACertificateDN = entry['attributes'].get('cACertificateDN')
		adi.certificateTemplates = entry['attributes'].get('certificateTemplates', [])
		for serverdef in entry['attributes'].get('msPKI-Enrollment-Servers', []):
			adi.enrollmentServers.append(serverdef.split('\n')[3])
		return adi
		
	def __str__(self):
		t = '== MSADEnrollmentService ==\r\n'
		t += "Name: %s\r\n" % self.name
		t += "DNS name: %s\r\n" % self.dNSHostName
		t += "Templates: %s\r\n" % ', '.join(self.certificateTemplates)
		if len(self.enrollmentServers) > 0:
			t += "Web services: %s\r\n" % ", ".join(self.enrollmentServers)
		t += "Certificate: \r\n%s\r\n" % print_cert(self.cACertificate.native, 2)

		return t
