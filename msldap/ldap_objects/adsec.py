#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#


from winacl.dtyp.sid import SID
from msldap.ldap_objects.common import MSLDAP_UAC, vn

class MSADTokenGroup:
	def __init__(self):
		self.cn = None #str
		self.distinguishedName = None #dn
		self.objectGUID = None
		self.objectSid = None
		self.tokengroups = []
	
	@staticmethod
	def from_ldap(entry):
		t = MSADTokenGroup()
		t.cn = entry['attributes'].get('cn')
		t.distinguishedName = entry['attributes'].get('distinguishedName')
		t.objectGUID = entry['attributes'].get('objectGUID')
		t.objectSid = entry['attributes'].get('objectSid')
		for sid_data in entry['attributes']['tokenGroups']:
			t.tokengroups.append(SID.from_bytes(sid_data))
		return t
		
	def __str__(self):
		t = '== MSADTokenGroup ==\r\n'
		t+= 'cn : %s\r\n' % self.cn
		t+= 'distinguishedName : %s\r\n' % self.distinguishedName
		t+= 'objectGUID : %s\r\n' % self.objectGUID
		t+= 'objectSid : %s\r\n' % self.objectSid
		t+= 'tokengroups : %s\r\n' % [str(x) for x in self.tokengroups]

		return t
	

class MSADSecurityInfo:
	ATTRS = [ 'sn', 'cn', 'objectClass','distinguishedName', 'nTSecurityDescriptor', 'objectGUID', 'objectSid']

	def __init__(self):
		self.sn = None #str
		self.cn = None #str
		self.distinguishedName = None #dn
		self.nTSecurityDescriptor = None
		self.objectGUID = None
		self.objectSid = None
		self.objectClass = None
		
	@staticmethod
	def from_ldap(entry):
		adi = MSADSecurityInfo()
		adi.sn = entry['attributes'].get('sn') 
		adi.cn = entry['attributes'].get('cn') 
		adi.distinguishedName = entry['attributes'].get('distinguishedName')
		adi.objectGUID = entry['attributes'].get('objectGUID')
		adi.objectSid = entry['attributes'].get('objectSid')
		adi.objectClass = entry['attributes'].get('objectClass')
		adi.nTSecurityDescriptor = entry['attributes'].get('nTSecurityDescriptor')

		return adi
		
		
	def __str__(self):
		t = '== MSADSecurityInfo ==\r\n'
		t+= 'sn : %s\r\n' % self.sn
		t+= 'cn : %s\r\n' % self.cn
		t+= 'distinguishedName : %s\r\n' % self.distinguishedName
		t+= 'objectGUID : %s\r\n' % self.objectGUID
		t+= 'objectSid : %s\r\n' % self.objectSid
		t+= 'nTSecurityDescriptor : %s\r\n' % self.nTSecurityDescriptor

		return t