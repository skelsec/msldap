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

class TrustDirection(enum.Enum): #enum.IntFlag << the actual type is intflag, but noone cares
	DISABLED = 0x00000000 #: Absence of any flags. The trust relationship exists but has been disabled.
	INBOUND = 0x00000001 #): The trusted domain trusts the primary domain to perform operations such as name lookups and authentication. If this flag is set, then the trustAuthIncoming attribute is present on this object.
	OUTBOUND = 0x00000002 #: The primary domain trusts the trusted domain to perform operations such as name lookups and authentication. If this flag is set, then the trustAuthOutgoing attribute is present on this object.
	BIDIRECTIONAL = 0x00000003 #: OR'ing of the preceding flags and behaviors representing that both domains trust one another for operations such as name lookups and authentication.

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
		return '%s %s %s %s' % (self.name, self.trustType, self.trustDirection, self.securityIdentifier)
		
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