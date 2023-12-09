#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from msldap.wintypes import *
from msldap.ldap_objects.common import MSLDAP_UAC, vn
from winacl.dtyp.sid import SID
from msldap.commons.utils import bh_dt_convert


MSADGroup_ATTRS = [ 	
	'cn', 'distinguishedName', 'objectGUID', 'objectSid', 'groupType', 
	'instanceType', 'name', 'member', 'sAMAccountName', 'systemFlags', 
	'whenChanged', 'whenCreated', 'description', 'nTSecurityDescriptor',
	'sAMAccountType', 'adminCount', 'isDeleted'
]

MSADGroup_highvalue = ["S-1-5-32-544", "S-1-5-32-550", "S-1-5-32-549", "S-1-5-32-551", "S-1-5-32-548"]



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
		self.adminCount = None
		self.isDeleted = None
		
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
		d['adminCount'] = self.adminCount
		d['isDeleted'] = self.isDeleted

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
		t.adminCount = entry['attributes'].get('adminCount')
		t.isDeleted = entry['attributes'].get('isDeleted')
		
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
	
	def get_row(self, attrs):
		t = self.to_dict()
		return [str(t.get(x)) if x[:4]!='UAC_' else str(self.uac_to_textflag(x)) for x in attrs]

	def __str__(self):
		t = 'MSADGroup\r\n'
		for x in self.__dict__:
			if not isinstance(self.__dict__[x], (list, dict)):
				t += '%s: %s\r\n' % (x, str(self.__dict__[x]))
			else:
				t += '%s: %s\r\n' % (x, self.__dict__[x])
		return t

	def to_bh(self, domain):
		# Thx Dirk-jan
		def is_highvalue(sid:str):
			if sid.endswith("-512") or sid.endswith("-516") or sid.endswith("-519") or sid.endswith("-520"):
				return True
			if sid in MSADGroup_highvalue:
				return True
			return False

		return {
			'Aces' : [],
			'Members': [],
			'ObjectIdentifier' : self.objectSid,
			"IsDeleted": bool(self.isDeleted),
			"IsACLProtected": False , # Post processing
			'Properties' : {
				'name' : '%s@%s' % (self.name.upper(), domain.upper()),
				'domain' : domain,
				'domainsid' : str(self.objectSid).rsplit('-',1)[0] , 
				'distinguishedname' : str(self.distinguishedName).upper(), 
				'highvalue' : is_highvalue(str(self.objectSid)),
				'admincount' : bool(self.adminCount),
				'description' : self.description ,
				'samaccountname' : self.sAMAccountName ,
				'whencreated' : bh_dt_convert(self.whenCreated),
			},
		}