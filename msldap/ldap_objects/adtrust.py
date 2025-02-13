#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum

from winacl.dtyp.sid import SID
from msldap.ldap_objects.common import MSLDAP_UAC, vn

MSADDomainTrust_ATTRS = [ 
	'sn', 
	'cn', 
	'objectClass',
	'distinguishedName', 
	'nTSecurityDescriptor', 
	'objectGUID', 
	'instanceType', 
	'whenCreated', 
	'whenChanged', 
	'name', 
	'securityIdentifier', 
	'trustDirection', 
	'trustPartner', 
	'trustPosixOffset', 
	'trustType', 
	'trustAttributes', 
	'flatName', 
	'dSCorePropagationData',
]


class TrustType(enum.Enum):
	DOWNLEVEL = 0x00000001 #): The trusted domain is a Windows domain not running Active Directory.
	UPLEVEL = 0x00000002 #): The trusted domain is a Windows domain running Active Directory.
	MIT = 0x00000003 #): The trusted domain is running a non-Windows, RFC4120-compliant Kerberos distribution. This type of trust is distinguished in that (1) a SID is not required for the TDO, and (2) the default key types include the DES-CBC and DES-CRC encryption types (see [RFC4120] section 8.1).
	DCE = 0x00000004 #): Historical reference; this value is not used in Windows.

# From: https://msdn.microsoft.com/en-us/library/cc223768.aspx
class TrustDirection(enum.Enum): #enum.IntFlag << the actual type is intflag, but noone cares
	DISABLED = 0x00000000 #: Absence of any flags. The trust relationship exists but has been disabled.
	INBOUND = 0x00000001 #): The trusted domain trusts the primary domain to perform operations such as name lookups and authentication. If this flag is set, then the trustAuthIncoming attribute is present on this object.
	OUTBOUND = 0x00000002 #: The primary domain trusts the trusted domain to perform operations such as name lookups and authentication. If this flag is set, then the trustAuthOutgoing attribute is present on this object.
	BIDIRECTIONAL = 0x00000003 #: OR'ing of the preceding flags and behaviors representing that both domains trust one another for operations such as name lookups and authentication.

# https://msdn.microsoft.com/en-us/library/cc223779.aspx
class TrustAttributes(enum.IntFlag):
	NON_TRANSITIVE = 0x00000001 #If this bit is set, then the trust cannot be used transitively. For example, if domain A trusts domain B, which in turn trusts domain C, and the A<-->B trust has this attribute set, then a client in domain A cannot authenticate to a server in domain C over the A<-->B<-->C trust linkage
	UPLEVEL_ONLY = 0x00000002 #If this bit is set in the attribute, then only Windows 2000 operating system and newer clients can use the trust link. Netlogon does not consume trust objects that have this flag set.
	QUARANTINED_DOMAIN = 0x00000004 #If this bit is set, the trusted domain is quarantined and is subject to the rules of SID Filtering as described in [MS-PAC] section 4.1.2.2.
	FOREST_TRANSITIVE = 0x00000008 #If this bit is set, the trust link is a cross-forest trust [MS-KILE] between the root domains of two forests, both of which are running in a forest functional level of DS_BEHAVIOR_WIN2003 or greater.  Only evaluated on Windows Server 2003 operating system and later. Can only be set if forest and trusted forest are running in a forest functional level of DS_BEHAVIOR_WIN2003 or greater.
	CROSS_ORGANIZATION = 0x00000010 # If this bit is set, then the trust is to a domain or forest that is not part of the organization. The behavior controlled by this bit is explained in [MS-KILE] section 3.3.5.7.5 and [MS-APDS] section 3.1.5. Only evaluated on Windows Server 2003 and later. Can only be set if forest and trusted forest are running in a forest functional level of DS_BEHAVIOR_WIN2003 or greater.
	WITHIN_FOREST = 0x00000020 #If this bit is set, then the trusted domain is within the same forest. Only evaluated on Windows Server 2003 and later.
	TREAT_AS_EXTERNAL = 0x00000040 #If this bit is set, then a cross-forest trust to a domain is to be treated as an external trust for the purposes of SID Filtering. Cross-forest trusts are more stringently filtered than external trusts. This attribute relaxes those cross-forest trusts to be equivalent to external trusts. For more information on how each trust type is filtered, see [MS-PAC] section 4.1.2.2. Only evaluated on Windows Server 2003 and later. Only evaluated if SID Filtering is used. Only evaluated on cross-forest trusts having TRUST_ATTRIBUTE_FOREST_TRANSITIVE. Can only be set if forest and trusted forest are running in a forest functional level of DS_BEHAVIOR_WIN2003 or greater.
	USES_RC4_ENCRYPTION = 0x00000080 #This bit is set on trusts with the trustType set to TRUST_TYPE_MIT, which are capable of using RC4 keys. Historically, MIT Kerberos distributions supported only DES and 3DES keys ([RFC4120], [RFC3961]). MIT 1.4.1 adopted the RC4HMAC encryption type common to Windows 2000 [MS-KILE], so trusted domains deploying later versions of the MIT distribution required this bit. For more information, see "Keys and Trusts", section 6.1.6.9.1. Only evaluated on TRUST_TYPE_MIT
	CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x00000200 #If this bit is set, tickets granted under this trust MUST NOT be trusted for delegation. The behavior controlled by this bit is as specified in [MS-KILE] section 3.3.5.7.5. Initially supported on Windows Server 2008 operating system and later. After [MSKB-4490425] is installed, this bit is superseded by the TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION bit.
	CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION = 0x00000800 # If this bit is set, tickets granted under this trust MUST be trusted for delegation. The behavior controlled by this bit is as specified in [MS-KILE] section 3.3.5.7.5. Only supported on Windows Server 2008 and later after [MSKB-4490425] updates are installed.
	PIM_TRUST  = 0x00000400 # If this bit and the TATE bit are set, then a cross-forest trust to a domain is to be treated as Privileged Identity Management trust for the purposes of SID Filtering. For more information on how each trust type is filtered, see [MS-PAC] section 4.1.2.2. Evaluated on Windows Server 2012 R2 operating system only with [MSKB-3155495] installed. Also evaluated on Windows Server 2016 operating system and later. Evaluated only if SID Filtering is used. Evaluated only on cross-forest trusts having TRUST_ATTRIBUTE_FOREST_TRANSITIVE.

	def __str__(self):
		if not self.value:
			return "NONE"
		return '|'.join(m.name for m in self.__class__ if m.value & self.value)

BH_TRUST_DIR_NAMING = {
	TrustDirection.DISABLED: 'Disabled',
	TrustDirection.INBOUND: 'Inbound',
	TrustDirection.OUTBOUND: 'Outbound',
	TrustDirection.BIDIRECTIONAL: 'Bidirectional'
}



class MSADDomainTrust:
	def __init__(self):
		self.sn = None #str
		self.cn = None #str
		self.distinguishedName = None #dn
		self.objectGUID = None

		self.instanceType = None
		self.whenCreated = None
		self.whenChanged = None
		self.name = None
		
		self.securityIdentifier = None
		self.trustDirection = None
		self.trustPartner = None
		self.trustPosixOffset = None
		self.trustType = None
		self.trustAttributes = None
		self.flatName = None
		self.dSCorePropagationData = None

		
	@staticmethod
	def from_ldap(entry):
		adi = MSADDomainTrust()
		adi.sn = entry['attributes'].get('sn') 
		adi.cn = entry['attributes'].get('cn') 
		adi.distinguishedName = entry['attributes'].get('distinguishedName')
		adi.objectGUID = entry['attributes'].get('objectGUID')
		adi.instanceType = entry['attributes'].get('instanceType')
		adi.whenCreated = entry['attributes'].get('whenCreated')
		adi.whenChanged = entry['attributes'].get('whenChanged')
		adi.name = entry['attributes'].get('name')
		adi.securityIdentifier = entry['attributes'].get('securityIdentifier')
		adi.trustDirection = entry['attributes'].get('trustDirection')
		adi.trustPartner = entry['attributes'].get('trustPartner')
		adi.trustPosixOffset = entry['attributes'].get('trustPosixOffset')
		adi.trustType = entry['attributes'].get('trustType')
		adi.trustAttributes = entry['attributes'].get('trustAttributes')
		adi.flatName = entry['attributes'].get('flatName')
		adi.dSCorePropagationData = entry['attributes'].get('dSCorePropagationData')

		if adi.securityIdentifier is not None:
			adi.securityIdentifier = SID.from_bytes(adi.securityIdentifier)
		if adi.trustType is not None:
			adi.trustType = TrustType(adi.trustType)
		if adi.trustDirection is not None:
			adi.trustDirection = TrustDirection(adi.trustDirection)
		return adi

	def to_dict(self):
		return {
			'sn' : self.sn,
			'cn' : self.cn,
			'distinguishedName' : self.distinguishedName,
			'objectGUID' : self.objectGUID,
			'instanceType' : self.instanceType,
			'whenCreated' : self.whenCreated,
			'whenChanged' : self.whenChanged,
			'name' : self.name,
			'securityIdentifier' : self.securityIdentifier,
			'trustDirection' : self.trustDirection,
			'trustPartner' : self.trustPartner,
			'trustPosixOffset' : self.trustPosixOffset,
			'trustType' : self.trustType,
			'trustAttributes' : self.trustAttributes,
			'flatName' : self.flatName,
			'dSCorePropagationData' : self.dSCorePropagationData,
		}
		
	def get_line(self):
		return '%s %s %s %s %s' % (self.name, self.trustType, self.trustDirection, TrustAttributes(self.trustAttributes), self.securityIdentifier)
		
	def __str__(self):
		t = '== MSADDomainTrust ==\r\n'
		t+= 'sn : %s\r\n' % self.sn
		t+= 'cn : %s\r\n' % self.cn
		t+= 'distinguishedName : %s\r\n' % self.distinguishedName
		t+= 'objectGUID : %s\r\n' % self.objectGUID
		t+= 'instanceType : %s\r\n' % self.instanceType
		t+= 'whenCreated : %s\r\n' % self.whenCreated
		t+= 'whenChanged : %s\r\n' % self.whenChanged
		t+= 'name : %s\r\n' % self.name
		t+= 'securityIdentifier : %s\r\n' % str(self.securityIdentifier)
		t+= 'trustDirection : %s\r\n' % self.trustDirection
		t+= 'trustPartner : %s\r\n' % self.trustPartner
		t+= 'trustPosixOffset : %s\r\n' % self.trustPosixOffset
		t+= 'trustType : %s\r\n' % self.trustType
		t+= 'trustAttributes : %s\r\n' % self.trustAttributes
		t+= 'flatName : %s\r\n' % self.flatName
		t+= 'dSCorePropagationData : %s\r\n' % self.dSCorePropagationData
		return t
	
	def get_row(self, attrs):
		t = self.to_dict()
		return [str(t.get(x)) for x in attrs]
	
	def to_bh(self):
		tat = TrustAttributes(self.trustAttributes)
		if TrustAttributes.WITHIN_FOREST in tat:
			is_transitive = True
			sid_filtering = TrustAttributes.QUARANTINED_DOMAIN in tat
		elif TrustAttributes.FOREST_TRANSITIVE in tat:
			is_transitive = True
			sid_filtering = True
		elif TrustAttributes.CROSS_ORGANIZATION in tat or TrustAttributes.TREAT_AS_EXTERNAL in tat:
			is_transitive = False
			sid_filtering = True
		else:
			is_transitive = TrustAttributes.NON_TRANSITIVE not in tat
			sid_filtering = True
		
		dname = self.name
		if self.name is None:
			dname = ''
		dname = dname.upper()

		return {
			"TargetDomainName": dname,
			"TargetDomainSid": str(self.securityIdentifier),
			"IsTransitive": is_transitive,
			"TrustDirection": self.trustDirection.value,
			"TrustType": self.trustType.value,
			"SidFilteringEnabled": sid_filtering
		}
		
