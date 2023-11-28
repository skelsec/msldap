#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from msldap.ldap_objects.common import MSLDAP_UAC, vn
from msldap.commons.utils import bh_dt_convert


MSADGPO_ATTRS = [
	'cn', 'displayName', 'distinguishedName', 'flags', 'gPCFileSysPath', 
	'gPCFunctionalityVersion', 'gPCMachineExtensionNames', 'gPCUserExtensionNames',
	'objectClass', 'objectGUID', 'systemFlags', 'versionNumber', 'whenChanged',
	'whenCreated', 'isDeleted', 'description'
]

class MSADGPO:
	def __init__(self):
		self.cn = None
		self.displayName = None
		self.distinguishedName = None
		self.flags = None
		self.gPCFileSysPath = None #str
		self.gPCFunctionalityVersion = None #str
		self.gPCMachineExtensionNames = None
		self.gPCUserExtensionNames = None
		self.objectClass = None #str
		self.objectGUID = None #uid
		self.systemFlags = None #str
		self.whenChanged = None #uid
		self.whenCreated = None #str
		self.versionNumber = None
		self.isDeleted = None
		self.description = None

	@staticmethod
	def from_ldap(entry, adinfo = None):
		adi = MSADGPO()
		adi.cn = entry['attributes'].get('cn') 
		adi.displayName = entry['attributes'].get('displayName')
		adi.distinguishedName = entry['attributes'].get('distinguishedName')
		adi.flags = entry['attributes'].get('flags')
		adi.gPCFileSysPath = entry['attributes'].get('gPCFileSysPath')
		adi.gPCFunctionalityVersion = entry['attributes'].get('gPCFunctionalityVersion')
		adi.gPCMachineExtensionNames = entry['attributes'].get('gPCMachineExtensionNames')
		adi.gPCUserExtensionNames = entry['attributes'].get('gPCUserExtensionNames')
		adi.objectClass = entry['attributes'].get('objectClass')
		adi.objectGUID = entry['attributes'].get('objectGUID')
		adi.systemFlags = entry['attributes'].get('systemFlags')
		adi.whenChanged = entry['attributes'].get('whenChanged')
		adi.whenCreated = entry['attributes'].get('whenCreated')
		adi.versionNumber = entry['attributes'].get('versionNumber')
		adi.isDeleted = entry['attributes'].get('isDeleted')
		adi.description = entry['attributes'].get('description')

		return adi

	def to_dict(self):
		t = {}
		t['cn'] = vn(self.cn)
		t['displayName'] = vn(self.displayName)
		t['distinguishedName'] = vn(self.distinguishedName)
		t['flags'] = vn(self.flags)
		t['gPCFileSysPath'] = vn(self.gPCFileSysPath)
		t['gPCFunctionalityVersion'] = vn(self.gPCFunctionalityVersion)
		t['gPCMachineExtensionNames'] = vn(self.gPCMachineExtensionNames)
		t['gPCUserExtensionNames'] = vn(self.gPCUserExtensionNames)
		t['systemFlags'] = vn(self.systemFlags)
		t['objectClass'] = vn(self.objectClass)
		t['objectGUID'] = vn(self.objectGUID)
		t['whenChanged'] = vn(self.whenChanged)
		t['whenCreated'] = vn(self.whenCreated)
		t['versionNumber'] = vn(self.versionNumber)
		t['isDeleted'] = vn(self.isDeleted)
		t['description'] = vn(self.description)
		return t
	
	def get_row(self, attrs):
		t = self.to_dict()
		return [str(t.get(x)) if x[:4]!='UAC_' else str(self.uac_to_textflag(x)) for x in attrs]

	def __str__(self):
		t = 'MSADUser\n'
		t += 'cn: %s\n' % self.cn 
		t += 'distinguishedName: %s\n' % self.distinguishedName 
		t += 'path: %s\n' % self.gPCFileSysPath 
		t += 'displayName: %s\n' % self.displayName 

		return t 

	def to_bh(self, domain, domainsid):
		return {
			'Aces' : [],
			'ObjectIdentifier' : self.objectGUID.upper(),
			"IsDeleted": bool(self.isDeleted),
			"IsACLProtected": False , # Post processing
			'Properties' : {
				'name' : '%s@%s' % (self.displayName.upper(), domain.upper()),
				'domain' : domain,
				'domainsid' : domainsid, 
				'distinguishedname' : str(self.distinguishedName).upper(), 
				'highvalue' : False, # TODO seems always false
				'whencreated' : bh_dt_convert(self.whenCreated),
				'description' : self.description,
				'gpcpath' : self.gPCFileSysPath.upper(),
			},
		}
