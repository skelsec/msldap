#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from msldap.commons.utils import bh_dt_convert
from msldap.commons.utils import FUNCTIONAL_LEVELS

MSADInfo_ATTRS = [
	'auditingPolicy', 'creationTime', 'dc', 'distinguishedName', 
	'forceLogoff', 'instanceType', 'lockoutDuration', 'lockOutObservationWindow', 
	'lockoutThreshold', 'masteredBy', 'maxPwdAge', 'minPwdAge', 'minPwdLength', 
	'name', 'nextRid', 'nTSecurityDescriptor', 'objectCategory', 'objectClass', 
	'objectGUID', 'objectSid', 'pwdHistoryLength', 
	'pwdProperties', 'serverState', 'systemFlags', 'uASCompat', 'uSNChanged', 
	'uSNCreated', 'whenChanged', 'whenCreated', 'rIDManagerReference',
	'msDS-Behavior-Version', 'description', 'isDeleted', 'gPLink', 'ms-DS-MachineAccountQuota'
]

class MSADInfo:
	def __init__(self):
		self.auditingPolicy = None #dunno
		self.creationTime = None #datetime
		self.dc = None #str
		self.distinguishedName = None #string
		self.forceLogoff = None #int
		self.instanceType = None #int
		self.lockoutDuration = None #int
		self.lockOutObservationWindow = None #int
		self.lockoutThreshold = None #int
		self.masteredBy = None #str
		self.maxPwdAge = None #int
		self.minPwdAge = None #int
		self.minPwdLength = None #int
		self.name = None #str
		self.nextRid = None #int
		self.nTSecurityDescriptor = None #str
		self.objectCategory = None #str
		self.objectClass = None #str
		self.objectGUID = None #str
		self.objectSid = None #str
		self.pwdHistoryLength = None #int
		self.pwdProperties = None #int
		self.serverState = None #int
		self.systemFlags = None #int
		self.uASCompat = None #int
		self.uSNChanged = None #int
		self.uSNCreated = None #int
		self.whenChanged = None #datetime
		self.whenCreated = None #datetime
		self.rIDManagerReference = None #str
		self.domainmodelevel = None
		self.description = None
		self.isDeleted = None
		self.gPLink = None
		self.machineAccountQuota = None
	
	@staticmethod
	def from_ldap(entry):
		adi = MSADInfo()
		adi.auditingPolicy = entry['attributes'].get('auditingPolicy') #dunno
		adi.creationTime = entry['attributes'].get('creationTime') #datetime
		adi.dc = entry['attributes'].get('dc') #str
		adi.distinguishedName = entry['attributes'].get('distinguishedName') #string
		adi.forceLogoff = entry['attributes'].get('forceLogoff') #int
		adi.instanceType = entry['attributes'].get('instanceType') #int
		adi.lockoutDuration = entry['attributes'].get('lockoutDuration') #int
		adi.lockOutObservationWindow = entry['attributes'].get('lockOutObservationWindow') #int
		adi.lockoutThreshold = entry['attributes'].get('lockoutThreshold') #int
		adi.masteredBy = entry['attributes'].get('masteredBy') #str
		adi.maxPwdAge = entry['attributes'].get('maxPwdAge') #int
		adi.minPwdAge = entry['attributes'].get('minPwdAge') #int
		adi.minPwdLength = entry['attributes'].get('minPwdLength') #int
		adi.name = entry['attributes'].get('name') #str
		adi.nextRid = entry['attributes'].get('nextRid') #int
		adi.nTSecurityDescriptor = entry['attributes'].get('nTSecurityDescriptor') #str
		adi.objectCategory = entry['attributes'].get('objectCategory') #str
		adi.objectClass = entry['attributes'].get('objectClass') #str
		adi.objectGUID = entry['attributes'].get('objectGUID') #str
		adi.objectSid = entry['attributes'].get('objectSid') #str
		adi.pwdHistoryLength = entry['attributes'].get('pwdHistoryLength') #int
		adi.pwdProperties = entry['attributes'].get('pwdProperties') #int
		adi.serverState = entry['attributes'].get('serverState') #int
		adi.systemFlags = entry['attributes'].get('systemFlags') #int
		adi.uASCompat = entry['attributes'].get('uASCompat') #int
		adi.uSNChanged = entry['attributes'].get('uSNChanged') #int
		adi.uSNCreated = entry['attributes'].get('uSNCreated') #int
		adi.whenChanged = entry['attributes'].get('whenChanged') #datetime
		adi.whenCreated = entry['attributes'].get('whenCreated') #datetime
		adi.rIDManagerReference = entry['attributes'].get('rIDManagerReference')
		adi.description = entry['attributes'].get('description')
		adi.isDeleted = entry['attributes'].get('isDeleted')
		adi.gPLink = entry['attributes'].get('gPLink')
		adi.machineAccountQuota = entry['attributes'].get('ms-DS-MachineAccountQuota')

		#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/564dc969-6db3-49b3-891a-f2f8d0a68a7f
		adi.domainmodelevel = entry['attributes'].get('msDS-Behavior-Version')

		return adi
	
	def to_dict(self):
		d = {}
		d['auditingPolicy'] = self.auditingPolicy
		d['creationTime'] = self.creationTime
		d['dc'] = self.dc
		d['distinguishedName'] = self.distinguishedName
		d['forceLogoff'] = self.forceLogoff
		d['instanceType'] = self.instanceType
		d['lockoutDuration'] = self.lockoutDuration
		d['lockOutObservationWindow'] = self.lockOutObservationWindow
		d['lockoutThreshold'] = self.lockoutThreshold
		d['masteredBy'] = self.masteredBy
		d['maxPwdAge'] = self.maxPwdAge
		d['minPwdAge'] = self.minPwdAge
		d['minPwdLength'] = self.minPwdLength
		d['name'] = self.name
		d['nextRid'] = self.nextRid
		d['nTSecurityDescriptor'] = self.nTSecurityDescriptor
		d['objectCategory'] = self.objectCategory
		d['objectClass'] = self.objectClass
		d['objectGUID'] = self.objectGUID
		d['objectSid'] = self.objectSid
		d['pwdHistoryLength'] = self.pwdHistoryLength
		d['pwdProperties'] = self.pwdProperties
		d['serverState'] = self.serverState
		d['systemFlags'] = self.systemFlags
		d['uASCompat'] = self.uASCompat
		d['uSNChanged'] = self.uSNChanged
		d['uSNCreated'] = self.uSNCreated
		d['whenChanged'] = self.whenChanged
		d['whenCreated'] = self.whenCreated
		d['domainmodelevel'] = self.domainmodelevel
		d['description'] = self.description
		d['ms-DS-MachineAccountQuota'] = self.machineAccountQuota
		return d


	def __str__(self):
		t = 'MSADInfo\n'
		t += 'auditingPolicy: %s\n' % self.auditingPolicy 
		t += 'creationTime: %s\n' % self.creationTime 
		t += 'dc: %s\n' % self.dc 
		t += 'distinguishedName: %s\n' % self.distinguishedName 
		t += 'forceLogoff: %s\n' % self.forceLogoff 
		t += 'instanceType: %s\n' % self.instanceType 
		t += 'lockoutDuration: %s\n' % self.lockoutDuration 
		t += 'lockOutObservationWindow: %s\n' % self.lockOutObservationWindow 
		t += 'lockoutThreshold: %s\n' % self.lockoutThreshold 
		t += 'masteredBy: %s\n' % self.masteredBy 
		t += 'maxPwdAge: %s\n' % self.maxPwdAge 
		t += 'minPwdAge: %s\n' % self.minPwdAge 
		t += 'minPwdLength: %s\n' % self.minPwdLength 
		t += 'name: %s\n' % self.name 
		t += 'nextRid: %s\n' % self.nextRid 
		t += 'nTSecurityDescriptor: %s\n' % self.nTSecurityDescriptor 
		t += 'objectCategory: %s\n' % self.objectCategory 
		t += 'objectClass: %s\n' % self.objectClass 
		t += 'objectGUID: %s\n' % self.objectGUID 
		t += 'objectSid: %s\n' % self.objectSid 
		t += 'pwdHistoryLength: %s\n' % self.pwdHistoryLength
		t += 'pwdProperties: %s\n' % self.pwdProperties
		t += 'serverState: %s\n' % self.serverState
		t += 'systemFlags: %s\n' % self.systemFlags
		t += 'uASCompat: %s\n' % self.uASCompat
		t += 'uSNChanged: %s\n' % self.uSNChanged
		t += 'uSNCreated: %s\n' % self.uSNCreated
		t += 'whenChanged: %s\n' % self.whenChanged
		t += 'whenCreated: %s\n' % self.whenCreated
		t += 'domainmodelevel: %s\n' % self.domainmodelevel
		t += 'description: %s\n' % self.description
		t += 'isDeleted: %s\n' % self.isDeleted
		t += 'gPLink: %s\n' % self.gPLink
		t += 'ms-DS-MachineAccountQuota: %s\n' % self.machineAccountQuota
		return t
	
	def get_row(self, attrs):
		t = self.to_dict()
		return [str(t.get(x)) for x in attrs]
	
	def to_bh(self, domain):
		try:
			functional_level = FUNCTIONAL_LEVELS[int(self.domainmodelevel)]
		except KeyError:
			functional_level = 'Unknown'
		return {
			'_gPLink' : self.gPLink, #always empty
			'Aces' : [],
			'ObjectIdentifier' : str(self.objectSid),
			"IsDeleted": bool(self.isDeleted),
			"IsACLProtected": False , # Post processing
			"Trusts" : [], #Post processing
			"ChildObjects": [], #Post processing
			"GPOChanges" : {
				"LocalAdmins": [],
				"RemoteDesktopUsers": [],
				"DcomUsers": [],
				"PSRemoteUsers": [],
				"AffectedComputers": []
			},
			"Links": [], # Post processing
			'Properties' : {
				'name' : domain,
				'domain' : domain,
				'domainsid' : str(self.objectSid).rsplit('-',1)[0] , 
				'distinguishedname' : str(self.distinguishedName).upper(), 
				'description' : self.description,
				'functionallevel' : functional_level,
				'highvalue' : True,
				'whencreated' : bh_dt_convert(self.whenCreated),
			}
			
		}