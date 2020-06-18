#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from msldap.wintypes import *
from msldap.ldap_objects.common import MSLDAP_UAC, vn
from winacl.dtyp.sid import SID

MSADGroup_ATTRS = [ 	
	'cn', 'distinguishedName', 'objectGUID', 'objectSid', 'groupType', 
	'instanceType', 'name', 'member', 'sAMAccountName', 'systemFlags', 
	'whenChanged', 'whenCreated', 'description', 'nTSecurityDescriptor',
	'sAMAccountType',
]


class MSADGroup:
	def __init__(self):
		self.cn = None #str
		self.distinguishedName = None #dn
		self.objectGUID = None
		self.objectSid = None
		self.description = None
		self.groupType = None
		self.instanceType = None
		self.name = None
		self.member = None
		self.nTSecurityDescriptor = None
		self.sAMAccountName = None
		self.sAMAccountType = None
		self.systemFlags = None
		self.whenChanged = None
		self.whenCreated = None
		
	def to_dict(self):
		d = {}
		d['cn'] = self.cn
		d['distinguishedName'] = self.distinguishedName
		d['objectGUID'] = self.objectGUID
		d['objectSid'] = self.objectSid
		d['description'] = self.description
		d['groupType'] = self.groupType
		d['instanceType'] = self.instanceType
		d['name'] = self.name
		d['member'] = self.member
		d['nTSecurityDescriptor'] = self.nTSecurityDescriptor
		d['sAMAccountName'] = self.sAMAccountName
		d['sAMAccountType'] = self.sAMAccountType
		d['systemFlags'] = self.systemFlags
		d['whenChanged'] = self.whenChanged
		d['whenCreated'] = self.whenCreated

		return d	
	
	@staticmethod
	def from_ldap(entry):
		t = MSADGroup()
		t.cn = entry['attributes'].get('cn')
		t.distinguishedName = entry['attributes'].get('distinguishedName')
		t.objectGUID = entry['attributes'].get('objectGUID')
		t.objectSid = entry['attributes'].get('objectSid')
		t.groupType = entry['attributes'].get('groupType')
		t.instanceType = entry['attributes'].get('instanceType')
		t.name = entry['attributes'].get('name')
		t.member = entry['attributes'].get('member')
		t.sAMAccountName = entry['attributes'].get('sAMAccountName')
		t.systemFlags = entry['attributes'].get('systemFlags')
		t.whenChanged = entry['attributes'].get('whenChanged')
		t.whenCreated = entry['attributes'].get('whenCreated')
		
		t.description =  entry['attributes'].get('description')
		if isinstance(t.description, list):
			if len(t.description) == 1:
				t.description = t.description[0]
			else:
				t.description = ', '.join(t.description)
		
		
		#temp = entry['attributes'].get('nTSecurityDescriptor')
		#if temp:
		#	t.nTSecurityDescriptor = SID.from_bytes(temp)
		return t
		

	def __str__(self):
		t = 'MSADGroup\r\n'
		for x in self.__dict__:
			if not isinstance(self.__dict__[x], (list, dict)):
				t += '%s: %s\r\n' % (x, str(self.__dict__[x]))
			else:
				t += '%s: %s\r\n' % (x, self.__dict__[x])
		return t