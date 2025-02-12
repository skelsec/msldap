import enum
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.ace import ACEType, ACE_OBJECT_PRESENCE, ACCESS_MASK, ADS_ACCESS_MASK


EX_RIGHT_CERTIFICATE_ENROLLMENT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
EX_RIGHT_CERTIFICATE_AUTOENROLLMENT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"


class CertificateNameFlag(enum.IntFlag):
	ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
	ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
	SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
	SUBJECT_ALT_REQUIRE_SPN = 0x00800000
	SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
	SUBJECT_ALT_REQUIRE_UPN = 0x02000000
	SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
	SUBJECT_ALT_REQUIRE_DNS = 0x08000000
	SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
	SUBJECT_REQUIRE_EMAIL = 0x20000000
	SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
	SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000
	OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008

class EnrollmentFlag(enum.IntFlag):
	INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
	PEND_ALL_REQUESTS = 0x00000002
	PUBLISH_TO_KRA_CONTAINER = 0x00000004
	PUBLISH_TO_DS = 0x00000008
	AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
	AUTO_ENROLLMENT = 0x00000020
	PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
	USER_INTERACTION_REQUIRED = 0x00000100
	REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
	ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
	ADD_OCSP_NOCHECK = 0x00001000
	ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
	NOREVOCATIONINFOINISSUEDCERTS = 0x00004000
	INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
	ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
	ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
	SKIP_AUTO_RENEWAL = 0x00040000
	NO_SECURITY_EXTENSION = 0x00080000

class PrivateKeyFlag(enum.IntFlag):
	REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001
	EXPORTABLE_KEY = 0x00000010
	STRONG_KEY_PROTECTION_REQUIRED = 0x00000020
	REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040
	REQUIRE_SAME_KEY_RENEWAL = 0x00000080
	USE_LEGACY_PROVIDER = 0x00000100
	ATTEST_REQUIRED = 0x000002000
	ATTEST_PREFERRED = 0x000001000
	HELLO_LOGON_KEY = 0x00200000

EKU_CLIENT_AUTHENTICATION_OID = "1.3.6.1.5.5.7.3.2"
EKU_PKINIT_CLIENT_AUTHENTICATION_OID = "1.3.6.1.5.2.3.4"
EKU_SMART_CARD_LOGON_OID = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY_PURPOSE_OID = "2.5.29.37.0"
EKU_CERTIFICATE_REQUEST_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"

EKUS_NAMES = {
    "1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
    "1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
    "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
    "1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
    "1.3.6.1.4.1.311.10.3.7": "OEM Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
    "1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
    "1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
    "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
    "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
    "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
    "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.10.3.30": "Disallowed List",
    "1.3.6.1.4.1.311.10.3.19": "Revoked List Signer",
    "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
    "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.9": "Root List Signer",
    "1.3.6.1.4.1.311.10.5.1": "Digital Rights",
    "1.3.6.1.4.1.311.10.6.2": "License Server Verification",
    "1.3.6.1.4.1.311.10.6.1": "Key Pack Licenses",
    EKU_SMART_CARD_LOGON_OID: "Smart Card Logon",
    EKU_CERTIFICATE_REQUEST_AGENT_OID: "Certificate Request Agent",
    "1.3.6.1.4.1.311.20.1": "CTL Usage",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival",
    "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
    "1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Driver",
    "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
    "1.3.6.1.4.1.311.64.1.1": "Domain Name System (DNS) Server Trust",
    "1.3.6.1.4.1.311.76.6.1": "Windows Update",
    "1.3.6.1.4.1.311.76.3.1": "Windows Store",
    "1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generator",
    "1.3.6.1.4.1.311.76.8.1": "Microsoft Publisher",
    "1.3.6.1.4.1.311.80.1": "Document Encryption",
    EKU_PKINIT_CLIENT_AUTHENTICATION_OID: "PKINIT Client Authentication",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.5.5.7.3.7": "IP security user",
    EKU_CLIENT_AUTHENTICATION_OID: "Client Authentication",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.5": "IP security end system",
    "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
    "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    EKU_ANY_PURPOSE_OID: "Any Purpose",
    "2.23.133.8.1": "Endorsement Key Certificate",
    "2.23.133.8.2": "Platform Certificate",
    "2.23.133.8.3": "Attestation Identity Key Certificate",
}

ENROLLMENT_FLAGS_NAMES = {
    EnrollmentFlag.INCLUDE_SYMMETRIC_ALGORITHMS: "INCLUDE_SYMMETRIC_ALGORITHMS",
    EnrollmentFlag.PEND_ALL_REQUESTS: "PEND_ALL_REQUESTS",
    EnrollmentFlag.PUBLISH_TO_KRA_CONTAINER: "PUBLISH_TO_KRA_CONTAINER",
    EnrollmentFlag.PUBLISH_TO_DS: "PUBLISH_TO_DS",
    EnrollmentFlag.AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE: "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
    EnrollmentFlag.AUTO_ENROLLMENT: "AUTO_ENROLLMENT",
    EnrollmentFlag.PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT: "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
    EnrollmentFlag.USER_INTERACTION_REQUIRED: "USER_INTERACTION_REQUIRED",
    EnrollmentFlag.REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE: "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
    EnrollmentFlag.ALLOW_ENROLL_ON_BEHALF_OF: "ALLOW_ENROLL_ON_BEHALF_OF",
    EnrollmentFlag.ADD_OCSP_NOCHECK: "ADD_OCSP_NOCHECK",
    EnrollmentFlag.ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL: "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
    EnrollmentFlag.NOREVOCATIONINFOINISSUEDCERTS: "NOREVOCATIONINFOINISSUEDCERTS",
    EnrollmentFlag.INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS: "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
    EnrollmentFlag.ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT: "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT",
    EnrollmentFlag.ISSUANCE_POLICIES_FROM_REQUEST: "ISSUANCE_POLICIES_FROM_REQUEST",
    EnrollmentFlag.SKIP_AUTO_RENEWAL: "SKIP_AUTO_RENEWAL",
}

MSADCertificateTemplate_ATTRS = [
		'cn', 'sn', 'distinguishedName', 'name', 'msPKI-RA-Application-Policies', 'msPKI-Certificate-Application-Policy', 
		'msPKI-Template-Schema-Version', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 
		'msPKI-Private-Key-Flag', 'pKIExtendedKeyUsage', 'nTSecurityDescriptor'
]

class MSADCertificateTemplate:
	def __init__(self):
		self.sn = None #str
		self.cn = None #str
		self.distinguishedName = None #dn
		self.name = None
		self.RA_Application_Policies = None
		self.Certificate_Application_Policy = None
		self.Template_Schema_Version = None
		self.Certificate_Name_Flag = None
		self.Enrollment_Flag = None
		self.RA_Signature = None
		self.Private_Key_Flag = None
		self.pKIExtendedKeyUsage = None
		self.nTSecurityDescriptor:SECURITY_DESCRIPTOR = None

		self.vulns = []
		self.enroll_sids = set()
		self.autoenroll_sids = set()
		self.write_owner_sids = set()
		self.write_dacl_sids = set()
		self.write_property_sids = set()
		self.fullcontrol_sids = set()
		self.allextendedrights_sids = set()
		self.sid_lookup_table = None
		self.enroll_services = []
		
	@staticmethod
	def from_ldap(entry):
		adi = MSADCertificateTemplate()
		adi.sn = entry['attributes'].get('sn') 
		adi.cn = entry['attributes'].get('cn') 
		adi.distinguishedName = entry['attributes'].get('distinguishedName')
		adi.name = entry['attributes'].get('name')
		adi.RA_Application_Policies = entry['attributes'].get('msPKI-RA-Application-Policies')
		adi.Certificate_Application_Policy = entry['attributes'].get('msPKI-Certificate-Application-Policy')
		adi.Template_Schema_Version = entry['attributes'].get('msPKI-Template-Schema-Version')
		adi.Certificate_Name_Flag = entry['attributes'].get('msPKI-Certificate-Name-Flag')
		adi.Enrollment_Flag = entry['attributes'].get('msPKI-Enrollment-Flag')
		adi.RA_Signature = entry['attributes'].get('msPKI-RA-Signature')
		adi.Private_Key_Flag = entry['attributes'].get('msPKI-Private-Key-Flag')
		adi.pKIExtendedKeyUsage = entry['attributes'].get('pKIExtendedKeyUsage', [])
		adi.nTSecurityDescriptor = entry['attributes'].get('nTSecurityDescriptor')
		if adi.nTSecurityDescriptor is not None:
			adi.nTSecurityDescriptor = SECURITY_DESCRIPTOR.from_bytes(adi.nTSecurityDescriptor)
		
		adi.calc_aces()
		return adi
	
	def isLowPrivSid(self, sid):
		sid = str(sid)
		if sid in ['S-1-1-0', 'S-1-5-11']:
			return True
		if sid.startswith('S-1-5-21-') is True and sid.rsplit('-',1)[1] in ['513','515','545']:
			return True
		return False

	def allows_authentication(self):
		return self.can_be_used_for_any_purpose() or len(set([EKU_CLIENT_AUTHENTICATION_OID, EKU_SMART_CARD_LOGON_OID, EKU_PKINIT_CLIENT_AUTHENTICATION_OID]).intersection(set(self.pKIExtendedKeyUsage))) > 0
	
	def can_be_used_for_any_purpose(self):
		return len(self.pKIExtendedKeyUsage) == 0 or EKU_ANY_PURPOSE_OID in self.pKIExtendedKeyUsage
	
	def requires_manager_approval(self):
		return EnrollmentFlag.PEND_ALL_REQUESTS in EnrollmentFlag(self.Enrollment_Flag)
	
	def requires_authorized_signatures(self):
		return self.RA_Signature != None and self.RA_Signature > 0
	
	def allows_to_specify_san(self):
		return CertificateNameFlag(self.Certificate_Name_Flag) & CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT > 0

	def allows_to_request_agent_certificate(self):
		return EKU_CERTIFICATE_REQUEST_AGENT_OID in self.pKIExtendedKeyUsage

	def allows_to_use_agent_certificate(self):
		if EKU_ANY_PURPOSE_OID in self.pKIExtendedKeyUsage:
			return True
		if EKU_CERTIFICATE_REQUEST_AGENT_OID in self.pKIExtendedKeyUsage:
			return True
		
		#return self.Template_Schema_Version == 1 \
        #    or (
        #        self.Template_Schema_Version > 1 \
        #        and self.RA_Signature == 1 \
        #        and EKU_CERTIFICATE_REQUEST_AGENT_OID in self.RA_Application_Policies
        #    )
	
	def no_securty_extension(self):
		return EnrollmentFlag.NO_SECURITY_EXTENSION in EnrollmentFlag(self.Enrollment_Flag)

	def is_vulnerable(self, tokengroups = None):		
		if tokengroups is None:
			if self.isLowPrivSid(str(self.nTSecurityDescriptor.Owner)) is True:
				return True, 'Owner is low priv user'
		
		else:
			if str(self.nTSecurityDescriptor.Owner) in tokengroups:
				return True, 'Owner can be controlled by current user'
		
		lowprivcanenroll = False
		if tokengroups is None:
			if any(self.isLowPrivSid(str(sid)) for sid in self.fullcontrol_sids) is True:
				return True, 'Lowpriv SID has full control'
			
			if any(self.isLowPrivSid(str(sid)) for sid in self.write_dacl_sids) is True:
				return True, 'Lowpriv SID can write DACLs'
			
			if any(self.isLowPrivSid(str(sid)) for sid in self.write_owner_sids) is True:
				return True, 'Lowpriv SID can change Owner'
			
			if any(self.isLowPrivSid(str(sid)) for sid in self.write_property_sids) is True:
				return True, 'Lowpriv SID can write property'
			
			if any(self.isLowPrivSid(str(sid)) for sid in self.enroll_sids) is True:
				lowprivcanenroll = True

			if any(self.isLowPrivSid(str(sid)) for sid in self.allextendedrights_sids) is True:
				lowprivcanenroll = True
				
		else:
			if len(self.enroll_sids.intersection(set(tokengroups))) > 0 or len(self.allextendedrights_sids.intersection(set(tokengroups))) > 0:
				lowprivcanenroll = True
			
			if len(self.write_dacl_sids.intersection(set(tokengroups))) > 0:
				return True, 'Current user can write DACLs'
			
			if len(self.write_owner_sids.intersection(set(tokengroups))) > 0:
				return True, 'Current user can change Owner'
			
			if len(self.write_property_sids.intersection(set(tokengroups))) > 0:
				return True, 'Current user can write property'
			
			if len(self.fullcontrol_sids.intersection(set(tokengroups))) > 0:
				return True, 'Current user has full control'

		if self.requires_manager_approval() is True:
			return False, 'Needs manager approval'
		
		if self.requires_authorized_signatures() is True:
			return False, 'Needs authorized signature'
		
		if self.allows_authentication() and lowprivcanenroll and self.allows_to_specify_san():
			return True, 'Enrollee supplies subject'
		
		if lowprivcanenroll and self.allows_to_use_agent_certificate() and self.allows_to_request_agent_certificate():
			return True, 'Certificate request agent'
		
		return False, 'No match found'
	
	def check_dangerous_permissions(self, tokengroups = None):
		issues = []
		if tokengroups is None or len(tokengroups) == 0:
			if self.isLowPrivSid(str(self.nTSecurityDescriptor.Owner)) is True:
				issues.append('Owner is low priv user')
				
			if any(self.isLowPrivSid(str(sid)) for sid in self.fullcontrol_sids) is True:
				issues.append('Lowpriv SID has full control')
			
			if any(self.isLowPrivSid(str(sid)) for sid in self.write_dacl_sids) is True:
				issues.append('Lowpriv SID can write DACLs')
			
			if any(self.isLowPrivSid(str(sid)) for sid in self.write_owner_sids) is True:
				issues.append('Lowpriv SID can change Owner')
			
			if any(self.isLowPrivSid(str(sid)) for sid in self.write_property_sids) is True:
				issues.append('Lowpriv SID can write property')
				
		else:			
			if len(self.write_dacl_sids.intersection(set(tokengroups))) > 0:
				issues.append('Current user can write DACLs')
			
			if len(self.write_owner_sids.intersection(set(tokengroups))) > 0:
				issues.append('Current user can change Owner')
			
			if len(self.write_property_sids.intersection(set(tokengroups))) > 0:
				issues.append('Current user can write property')
			
			if len(self.fullcontrol_sids.intersection(set(tokengroups))) > 0:
				issues.append('Current user has full control')
			
			if str(self.nTSecurityDescriptor.Owner) in tokengroups:
				issues.append('The current user can control the owner -or is the owner-')
		
		return issues
	
	def is_vulnerable2(self, tokengroups = None):
		vulns = {}
		if tokengroups is None:
			tokengroups = []

		user_can_enroll = False
		if len(set(self.enroll_sids).intersection(set(tokengroups))) > 0:
			user_can_enroll = True

		if user_can_enroll and self.allows_authentication() and self.allows_to_specify_san():
			vulns['ESC1'] = {
				'SIDs': self.enroll_sids,
				'Reason': 'Users can enroll, enrollee supplies subject and template allows client authentication'
			}
		
		if user_can_enroll and self.can_be_used_for_any_purpose() is True:
			vulns['ESC2'] = {
				'SIDs': self.enroll_sids,
				'Reason': 'Users can enroll and template allows any purpose'
			}
		
		if user_can_enroll and self.allows_to_use_agent_certificate():
			vulns['ESC3'] = {
				'SIDs': self.enroll_sids,
				'Reason': 'Users can enroll and template allows certificate request agent'
			}
		
		if user_can_enroll and self.no_securty_extension():
			vulns['ESC9'] = {
				'SIDs': self.enroll_sids,
				'Reason': 'Users can enroll and template does not require security extension'
			}

		perm_issues = self.check_dangerous_permissions(tokengroups)
		if len(perm_issues) > 0:
			vulns['ESC4'] = {
				'SIDs': tokengroups,
				'Reason': ', '.join(perm_issues)
			}
		return vulns
	
	def calc_aces(self):
		if self.nTSecurityDescriptor is None:
			return
		for ace in self.nTSecurityDescriptor.Dacl.aces:
			if ace.AceType != ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE and ace.AceType != ACEType.ACCESS_ALLOWED_ACE_TYPE:
				continue
			
			if ace.AceType == ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE:
				if str(ace.ObjectType) == EX_RIGHT_CERTIFICATE_ENROLLMENT:
					self.enroll_sids.add(str(ace.Sid))
				elif str(ace.ObjectType) == EX_RIGHT_CERTIFICATE_AUTOENROLLMENT:
					self.autoenroll_sids.add(str(ace.Sid))
				elif ADS_ACCESS_MASK.CONTROL_ACCESS in ADS_ACCESS_MASK(ace.Mask) and ace.ObjectType is None:
					self.allextendedrights_sids.add(str(ace.Sid))
				continue
			
			if ADS_ACCESS_MASK.GENERIC_ALL in ADS_ACCESS_MASK(ace.Mask):
				self.fullcontrol_sids.add(str(ace.Sid))
				
			if ADS_ACCESS_MASK.WRITE_DACL in ADS_ACCESS_MASK(ace.Mask):
				self.write_dacl_sids.add(str(ace.Sid))

			if ADS_ACCESS_MASK.WRITE_OWNER in ADS_ACCESS_MASK(ace.Mask):
				self.write_owner_sids.add(str(ace.Sid))
			
			if ADS_ACCESS_MASK.WRITE_PROP in ADS_ACCESS_MASK(ace.Mask):
				self.write_property_sids.add(str(ace.Sid))
			
			if ADS_ACCESS_MASK.CONTROL_ACCESS in ADS_ACCESS_MASK(ace.Mask):
				self.allextendedrights_sids.add(str(ace.Sid))
	
	@property
	def is_enabled(self):
		return len(self.enroll_services) > 0
	
	@property
	def enrollment_services(self):
		res = []
		for es in self.enroll_services:
			if es.find('\\') != -1:
				hostname, service = es.split('\\', 1)
				res.append((hostname, service))
			else:
				res.append((None, service))
		return res


	def __str__(self):
		t = '== MSADCertificateTemplate ==\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])

		return t

	def prettyprint(self):
		def print_sids(buffer, sidlist, offset = 6):
			for sid in sidlist:
				if self.sid_lookup_table is not None and sid in self.sid_lookup_table:
					buffer += '%s%s\\%s [%s]\r\n' % (offset*' ', self.sid_lookup_table[sid][0], self.sid_lookup_table[sid][1], sid)
				else:
					buffer += '%s%s\r\n' % (offset*' ', sid)
			return buffer

		t = '== MSADCertificateTemplate ==\r\n'
		t += "Name: %s\r\n" % self.name
		t += 'distinguishedName: %s\r\n' % self.distinguishedName
		t += "Schema Version: %s\r\n" % self.Template_Schema_Version

		if self.enroll_services:
			t += "Enroll Services: %s\r\n" % ", ".join(self.enroll_services)

		if len(self.vulns) > 0:
			t += "Vulnerabilities: %s\r\n" % ", ".join(self.vulns)
		
		if self.Certificate_Name_Flag is not None:
			x = str(CertificateNameFlag(self.Certificate_Name_Flag)).split('.',1)
			if len(x) >= 2:
				x = x[1].replace('|',', ')
			else:
				x = str(self.Certificate_Name_Flag).replace('|',', ')
			t += "msPKI-Certificate-Name-Flag: %s\r\n" % x
		if self.Enrollment_Flag is not None:
			x = str(EnrollmentFlag(self.Enrollment_Flag)).split('.',1)
			if len(x) >= 2:
				x = x[1].replace('|',', ')
			else:
				x = str(self.Enrollment_Flag).replace('|',', ')
			t += "msPKI-Enrollment-Flag: %s\r\n" % x
		if self.RA_Signature is not None:
			t += "msPKI-RA-Signature: %s\r\n" % self.RA_Signature
		if self.pKIExtendedKeyUsage is not None:
			t += "pKIExtendedKeyUsage: %s\r\n" % ", ".join([EKUS_NAMES.get(oid, oid) for oid in self.pKIExtendedKeyUsage])
		if self.Certificate_Application_Policy is not None:
			t += "msPKI-Certificate-Application-Policy: %s\r\n" % ", ".join([EKUS_NAMES.get(oid, oid) for oid in self.Certificate_Application_Policy])
		if self.RA_Application_Policies is not None:
			t += "msPKI-RA-Application-Policy: %s\r\n" % ", ".join([EKUS_NAMES.get(oid, oid) for oid in self.RA_Application_Policies])
		
		t += "Permissions\r\n"
		t += "  Enrollment Permissions\r\n"
		if len(self.enroll_sids) > 0:
			t += "    Enrollment Rights\r\n"
			t = print_sids(t, self.enroll_sids)
			
		if len(self.autoenroll_sids) > 0:
			t += "    AutoEnrollment Rights\r\n"
			t = print_sids(t, self.autoenroll_sids)
		
		if len(self.allextendedrights_sids) > 0:
			t += "    All Extended Rights\r\n"
			t = print_sids(t, self.allextendedrights_sids)
		
		t+= "  Object Control Permissions\r\n"
		t+= '    Owner\r\n'
		sid = str(self.nTSecurityDescriptor.Owner)
		if self.sid_lookup_table is not None and sid in self.sid_lookup_table:
			t += '      %s\\%s [%s]\r\n' % (self.sid_lookup_table[sid][0], self.sid_lookup_table[sid][1], sid)
		else:
			t += "      %s\r\n" % sid

		if len(self.fullcontrol_sids) > 0:
			t+= "    Full Control\r\n"
			t = print_sids(t, self.fullcontrol_sids)

		t += "    Write Owner\r\n"
		t = print_sids(t, self.write_owner_sids)

		t += "    Write DACL\r\n"
		t = print_sids(t, self.write_dacl_sids)

		t += "    Write Property\r\n"
		t = print_sids(t, self.write_property_sids)

		t += "    SDDL\r\n"
		t += self.nTSecurityDescriptor.to_sddl()
		t += '\r\n'
		return t

	def __str__(self):
		return self.prettyprint()
