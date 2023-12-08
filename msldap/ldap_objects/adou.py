#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import base64
from msldap.commons.utils import bh_dt_convert



MSADOU_ATTRS = [ 	
	'description', 'distinguishedName', 'dSCorePropagationData', 'gPLink', 'instanceType', 
	'isCriticalSystemObject', 'name', 'nTSecurityDescriptor', 'objectCategory', 'objectClass', 
	'objectGUID', 'ou', 'showInAdvancedViewOnly', 'systemFlags', 'uSNChanged', 'uSNCreated',
	'whenChanged', 'whenCreated', 'isDeleted'
]

class MSADOU:
	def __init__(self):
		self.description = None #dunno
		self.distinguishedName = None #datetime
		self.dSCorePropagationData = None #str
		self.gPLink = None #list
		self.instanceType = None #int
		self.isCriticalSystemObject = None #int
		self.name = None #int
		self.nTSecurityDescriptor = None #int
		self.objectCategory = None #int
		self.objectClass = None #str
		self.objectGUID = None #int
		self.ou = None #int
		self.showInAdvancedViewOnly = None #int
		self.systemFlags = None #str
		self.uSNChanged = None #int
		self.uSNCreated = None #str
		self.whenChanged = None #str
		self.whenCreated = None #str
		self.isDeleted = None #str
	
	@staticmethod
	def from_ldap(entry):
		adi = MSADOU()
		adi.description = entry['attributes'].get('description') #dunno
		adi.distinguishedName = entry['attributes'].get('distinguishedName') #datetime
		adi.dSCorePropagationData = entry['attributes'].get('dSCorePropagationData') #str
		adi.gPLink = entry['attributes'].get('gPLink') #list
		adi.instanceType = entry['attributes'].get('instanceType') #int
		adi.isCriticalSystemObject = entry['attributes'].get('isCriticalSystemObject') #int
		adi.name = entry['attributes'].get('name') #str
		adi.nTSecurityDescriptor = entry['attributes'].get('nTSecurityDescriptor') #str
		adi.objectCategory = entry['attributes'].get('objectCategory') #str
		adi.objectClass = entry['attributes'].get('objectClass') #str
		adi.objectGUID = entry['attributes'].get('objectGUID') #str
		adi.ou = entry['attributes'].get('ou') #str
		adi.showInAdvancedViewOnly = entry['attributes'].get('showInAdvancedViewOnly') #int
		adi.systemFlags = entry['attributes'].get('systemFlags') #int
		adi.uSNChanged = entry['attributes'].get('uSNChanged') #int
		adi.uSNCreated = entry['attributes'].get('uSNCreated') #int
		adi.whenChanged = entry['attributes'].get('whenChanged') #datetime
		adi.whenCreated = entry['attributes'].get('whenCreated') #datetime
		adi.isDeleted = entry['attributes'].get('isDeleted') #datetime
		return adi
	
	def to_dict(self):
		d = {}
		d['description'] = self.description
		d['distinguishedName'] = self.distinguishedName
		d['dSCorePropagationData'] = self.dSCorePropagationData
		d['gPLink'] = self.gPLink
		d['instanceType'] = self.instanceType
		d['isCriticalSystemObject'] = self.isCriticalSystemObject
		d['name'] = self.name
		d['nTSecurityDescriptor'] = self.nTSecurityDescriptor
		d['objectCategory'] = self.objectCategory
		d['objectClass'] = self.objectClass
		d['objectGUID'] = self.objectGUID
		d['ou'] = self.ou
		d['showInAdvancedViewOnly'] = self.showInAdvancedViewOnly
		d['systemFlags'] = self.systemFlags
		d['uSNChanged'] = self.uSNChanged
		d['uSNCreated'] = self.uSNCreated
		d['whenChanged'] = self.whenChanged
		d['whenCreated'] = self.whenCreated
		d['isDeleted'] = self.isDeleted
		return d

	def get_row(self, attrs):
		t = self.to_dict()
		if 'nTSecurityDescriptor' in attrs:
			if t['nTSecurityDescriptor'] is not None:
				t['nTSecurityDescriptor'] = base64.b64encode(t['nTSecurityDescriptor']).decode()
			else:
				t['nTSecurityDescriptor'] = b''
		return [str(t.get(x)) for x in attrs]

	def __str__(self):
		t = 'MSADOU\r\n'
		d = self.to_dict()
		for k in d:
			t += '%s: %s\r\n' % (k, d[k])
		return t 
	
	def to_bh(self, domain, domainsid):
		return {
			'Aces' : [],
			'Links'	: [],
			'ObjectIdentifier' : self.objectGUID.upper(),
			"IsDeleted": bool(self.isDeleted),
			"IsACLProtected": False , # Post processing
			'Properties' : {
				'name' : '%s@%s' % (self.name.upper(), domain.upper()),
				'domain' : domain,
				'domainsid' : domainsid, 
				'distinguishedname' : str(self.distinguishedName).upper(), 
				'highvalue' : False, # seems always false
				'whencreated' : bh_dt_convert(self.whenCreated),
				'description' : self.description ,				
				'blocksinheritance' : False, # seems always false
			},
			"GPOChanges": {
                "LocalAdmins": [],
                "RemoteDesktopUsers": [],
                "DcomUsers": [],
                "PSRemoteUsers": [],
                "AffectedComputers": []
            },
			'_gPLink' : self.gPLink,
		}