#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import base64
from msldap.commons.utils import bh_dt_convert



MSADContainer_ATTRS = [ 	
	'distinguishedName', 'name', 'objectGUID', 'isCriticalSystemObject','objectClass', 'objectCategory',
	'isDeleted', 'description', 'whenCreated'
]

class MSADContainer:
	def __init__(self):
		self.distinguishedName = None #datetime
		self.isCriticalSystemObject = None #int
		self.name = None #int
		self.objectCategory = None #int
		self.objectClass = None #str
		self.objectGUID = None #int
		self.isDeleted = None #str
		self.description = None
		self.whenCreated = None #datetime
	
	@staticmethod
	def from_ldap(entry):
		adi = MSADContainer()
		adi.distinguishedName = entry['attributes'].get('distinguishedName') #datetime
		adi.isCriticalSystemObject = entry['attributes'].get('isCriticalSystemObject') #int
		adi.name = entry['attributes'].get('name') #str
		adi.objectCategory = entry['attributes'].get('objectCategory') #str
		adi.objectClass = entry['attributes'].get('objectClass') #str
		adi.objectGUID = entry['attributes'].get('objectGUID') #str
		adi.isDeleted = entry['attributes'].get('isDeleted')
		adi.description = entry['attributes'].get('description')
		adi.whenCreated = entry['attributes'].get('whenCreated')
		return adi
	
	def to_dict(self):
		d = {}
		d['distinguishedName'] = self.distinguishedName
		d['isCriticalSystemObject'] = self.isCriticalSystemObject
		d['name'] = self.name
		d['objectCategory'] = self.objectCategory
		d['objectClass'] = self.objectClass
		d['objectGUID'] = self.objectGUID
		d['isDeleted'] = self.isDeleted
		d['description'] = self.description
		d['whenCreated'] = self.whenCreated
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
		t = 'MSADContainer\r\n'
		d = self.to_dict()
		for k in d:
			t += '%s: %s\r\n' % (k, d[k])
		return t 
	
	def to_bh(self, domain, domainsid):
		return {
			'Aces' : [],
			'ObjectIdentifier' : self.objectGUID.upper(),
			"IsDeleted": bool(self.isDeleted),
			"IsACLProtected": False , # Post processing
			"ChildObjects" : [], #Post processing
			'Properties' : {
				'name' : self.name,
				'domain' : domain,
				'domainsid' : domainsid, 
				'distinguishedname' : str(self.distinguishedName).upper(), 
				'highvalue' : False, # TODO but seems always false
				'whencreated' : bh_dt_convert(self.whenCreated),
				'description' : self.description ,				
			},
		}