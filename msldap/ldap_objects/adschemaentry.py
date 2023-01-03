#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

MSAD_SYNTAX_TYPE = {
	'2.5.5.1': 'str',
	'2.5.5.2': 'str',
	'2.5.5.3': 'str',
	'2.5.5.4': 'str',
	'2.5.5.5': 'str',
	'2.5.5.6': 'str',
	'2.5.5.7': 'str',
	'2.5.5.8': 'bool',
	'2.5.5.9': 'int',
	'2.5.5.10': 'bytes',
	'2.5.5.11': 'date',
	'2.5.5.12': 'str',
	'2.5.5.13': 'bstr',
	'2.5.5.14': 'str',
	'2.5.5.15': 'sd',
	'2.5.5.16': 'int',
	'2.5.5.17': 'sid',
}

MSADSCHEMAENTRY_ATTRS = [ 	
	'cn', 'distinguishedName', 'adminDescription', 
	'adminDisplayName', 'objectGUID', 'schemaIDGUID', 
	'lDAPDisplayName', 'name', 'attributeID', 
	'attributeSyntax', 'isSingleValued', 
	'isMemberOfPartialAttributeSet'
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
		self.attributeID = None
		self.attributeSyntax = None
		self.isSingleValued = None #str
		self.isMemberOfPartialAttributeSet = None

	
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
		adi.attributeID = entry['attributes'].get('attributeID')
		adi.attributeSyntax = entry['attributes'].get('attributeSyntax')
		adi.isSingleValued = entry['attributes'].get('isSingleValued')
		adi.isMemberOfPartialAttributeSet = entry['attributes'].get('isMemberOfPartialAttributeSet')

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
		d['attributeID'] = self.attributeID
		d['attributeSyntax'] = self.attributeSyntax
		d['isSingleValued'] = self.isSingleValued
		d['isMemberOfPartialAttributeSet'] = self.isMemberOfPartialAttributeSet
		
		return d

	def __str__(self):
		t = 'MSADSchemaEntry\r\n'
		d = self.to_dict()
		for k in d:
			t += '%s: %s\r\n' % (k, d[k])
		return t 
	
	def get_type(self):
		im = 'single' if self.isSingleValued is True else 'multi'
		return '%s_%s' % (im, MSAD_SYNTAX_TYPE[self.attributeSyntax])