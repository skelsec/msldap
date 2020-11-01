#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#


MSADSCHEMAENTRY_ATTRS = [ 	
	'cn', 'distinguishedName', 'adminDescription', 
	'adminDisplayName', 'objectGUID', 'schemaIDGUID', 
	'lDAPDisplayName', 'name', 
]

class MSADSchemaEntry:
	def __init__(self):
		self.cn = None #str
		self.distinguishedName = None #dn
		self.adminDescription = None #dunno
		self.adminDisplayName = None #datetime
		self.objectGUID = None #int
		self.schemaIDGUID = None
		self.lDAPDisplayName = None
		self.name = None #int

	
	@staticmethod
	def from_ldap(entry):
		adi = MSADSchemaEntry()
		adi.cn = entry['attributes'].get('cn') 
		adi.distinguishedName = entry['attributes'].get('distinguishedName')
		adi.adminDescription = entry['attributes'].get('adminDescription')
		adi.adminDisplayName = entry['attributes'].get('adminDisplayName')
		adi.objectGUID = entry['attributes'].get('objectGUID') #str
		adi.schemaIDGUID = entry['attributes'].get('schemaIDGUID') #list
		adi.lDAPDisplayName = entry['attributes'].get('lDAPDisplayName') #int
		adi.name = entry['attributes'].get('name') #int
		return adi
	
	def to_dict(self):
		d = {}
		d['cn'] = self.cn
		d['distinguishedName'] = self.distinguishedName
		d['adminDescription'] = self.adminDescription
		d['adminDisplayName'] = self.adminDisplayName
		d['objectGUID'] = self.objectGUID
		d['schemaIDGUID'] = self.schemaIDGUID
		d['lDAPDisplayName'] = self.lDAPDisplayName
		d['name'] = self.name
		return d


	def __str__(self):
		t = 'MSADSchemaEntry\r\n'
		d = self.to_dict()
		for k in d:
			t += '%s: %s\r\n' % (k, d[k])
		return t 