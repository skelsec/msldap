#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import datetime #, timedelta, timezone
from msldap.ldap_objects.common import MSLDAP_UAC, vn

MSADGMSAUser_ATTRS = [ 	
	'accountExpires', 'badPasswordTime', 'badPwdCount', 'cn', 'codePage', 
	'distinguishedName', 'lastLogoff', 'lastLogon', 'lastLogonTimestamp', 
	'logonCount', 'name', 'objectCategory', 'objectClass', 'objectGUID', 
	'objectSid', 'primaryGroupID', 'pwdLastSet', 'sAMAccountName', 
	'sAMAccountType', 'sn', 'userAccountControl', 'whenChanged', 'whenCreated',
	'dNSHostName', 'msDS-SupportedEncryptionTypes',	'msDS-ManagedPasswordId', 
	'msDS-ManagedPasswordInterval', 'msDS-GroupMSAMembership', 'msDS-ManagedPassword'
]
MSADGMSAUser_TSV_ATTRS = [
	'sAMAccountName', 'badPasswordTime', 'badPwdCount', 'pwdLastSet', 'lastLogonTimestamp',
	'whenCreated', 'whenChanged', 'objectSid', 'cn', 'UAC_SCRIPT', 'UAC_ACCOUNTDISABLE', 
	'UAC_LOCKOUT', 'UAC_PASSWD_NOTREQD', 'UAC_PASSWD_CANT_CHANGE', 'UAC_ENCRYPTED_TEXT_PASSWORD_ALLOWED', 
	'UAC_DONT_EXPIRE_PASSWD', 'UAC_USE_DES_KEY_ONLY', 'UAC_DONT_REQUIRE_PREAUTH', 'UAC_PASSWORD_EXPIRED'
]

class MSADGMSAUser:
	def __init__(self):
		## ID
		self.sn = None #str
		self.cn = None #str
		self.distinguishedName = None #dn
		self.displayName = None #str
		self.name = None #str
		self.objectCategory = None #dn
		self.objectClass = None #str
		self.objectGUID = None #uid
		self.objectSid = None #str
		self.primaryGroupID = None #uid
		self.sAMAccountName = None #str
		self.dNSHostName = None #str
		self.msDS_SupportedEncryptionTypes = None #int
		self.msDS_ManagedPasswordId = None #bytes
		self.msDS_ManagedPasswordInterval = None #str
		self.msDS_GroupMSAMembership = None #SD
		self.msDS_ManagedPassword = None #str

		## times
		self.accountExpires = None #datetime
		self.badPasswordTime = None #datetime
		self.lastLogoff = None #datetime
		self.lastLogon = None #datetime
		self.lastLogonTimestamp = None #datetime
		self.pwdLastSet = None #datetime
		self.whenChanged = None #datetime
		self.whenCreated = None #datetime

		## security
		self.badPwdCount = None #int
		self.logonCount = None #int
		self.sAMAccountType = None #int
		self.userAccountControl = None #UserAccountControl intflag
		
		## calculated properties
		self.when_pw_change = None #datetime
		self.when_pw_expires = None #datetime
		self.must_change_pw = None #datetime

	@staticmethod
	def from_ldap(entry, adinfo = None):
		adi = MSADGMSAUser()
		adi.sn = entry['attributes'].get('sn') 
		adi.cn = entry['attributes'].get('cn') 
		adi.distinguishedName = entry['attributes'].get('distinguishedName')
		adi.name = entry['attributes'].get('name')
		adi.objectCategory = entry['attributes'].get('objectCategory')
		adi.objectClass = entry['attributes'].get('objectClass')
		adi.objectGUID = entry['attributes'].get('objectGUID')
		adi.objectSid = entry['attributes'].get('objectSid')
		adi.primaryGroupID = entry['attributes'].get('primaryGroupID')
		adi.sAMAccountName = entry['attributes'].get('sAMAccountName')
		adi.accountExpires = entry['attributes'].get('accountExpires')
		adi.badPasswordTime = entry['attributes'].get('badPasswordTime')
		adi.lastLogoff = entry['attributes'].get('lastLogoff')
		adi.lastLogon = entry['attributes'].get('lastLogon')
		adi.lastLogonTimestamp = entry['attributes'].get('lastLogonTimestamp')
		adi.pwdLastSet = entry['attributes'].get('pwdLastSet')
		adi.whenChanged = entry['attributes'].get('whenChanged')
		adi.whenCreated = entry['attributes'].get('whenCreated')
		adi.badPwdCount = entry['attributes'].get('badPwdCount')
		adi.logonCount = entry['attributes'].get('logonCount')
		adi.sAMAccountType = entry['attributes'].get('sAMAccountType')
		adi.dNSHostName = entry['attributes'].get('dNSHostName')
		adi.msDS_SupportedEncryptionTypes = entry['attributes'].get('msDS-SupportedEncryptionTypes')
		adi.msDS_ManagedPasswordId = entry['attributes'].get('msDS-ManagedPasswordId')
		adi.msDS_ManagedPasswordInterval = entry['attributes'].get('msDS-ManagedPasswordInterval')
		adi.msDS_GroupMSAMembership = entry['attributes'].get('msDS-GroupMSAMembership')
		adi.msDS_ManagedPassword = entry['attributes'].get('msDS-ManagedPassword')
		
		temp = entry['attributes'].get('userAccountControl')
		if temp:
			adi.userAccountControl = MSLDAP_UAC(temp)
		return adi

	def to_dict(self):
		t = {}
		t['sn'] = vn(self.sn)
		t['cn'] = vn(self.cn)
		t['distinguishedName'] = vn(self.distinguishedName)
		t['name'] = vn(self.name)
		t['objectCategory'] = vn(self.objectCategory)
		t['objectClass'] = vn(self.objectClass)
		t['objectGUID'] = vn(self.objectGUID)
		t['objectSid'] = vn(self.objectSid)
		t['primaryGroupID'] = vn(self.primaryGroupID)
		t['sAMAccountName'] = vn(self.sAMAccountName)
		t['accountExpires'] = vn(self.accountExpires)
		t['badPasswordTime'] = vn(self.badPasswordTime)
		t['lastLogoff'] = vn(self.lastLogoff)
		t['lastLogon'] = vn(self.lastLogon)
		t['lastLogonTimestamp'] = vn(self.lastLogonTimestamp)
		t['pwdLastSet'] = vn(self.pwdLastSet)
		t['whenChanged'] = vn(self.whenChanged)
		t['whenCreated'] = vn(self.whenCreated)
		t['badPwdCount'] = vn(self.badPwdCount)
		t['logonCount'] = vn(self.logonCount)
		t['sAMAccountType'] = vn(self.sAMAccountType)
		t['userAccountControl'] = vn(self.userAccountControl)
		t['dNSHostName'] = vn(self.dNSHostName)
		t['msDS_SupportedEncryptionTypes'] = vn(self.msDS_SupportedEncryptionTypes)
		t['msDS_ManagedPasswordInterval'] = vn(self.msDS_ManagedPasswordInterval)
		t['msDS_GroupMSAMembership'] = vn(self.msDS_GroupMSAMembership)
		t['msDS_ManagedPassword'] = vn(self.msDS_ManagedPassword)
		t['msDS_ManagedPasswordId'] = vn(self.msDS_ManagedPasswordId)
		return t

	def uac_to_textflag(self, attr_s):
		if self.userAccountControl is None or self.userAccountControl == '':
			return 'N/A'
		attr = getattr(MSLDAP_UAC, attr_s[4:])
		if self.userAccountControl & attr:
			return True
		return False

	def get_row(self, attrs):
		t = self.to_dict()
		return [str(t.get(x)) if x[:4]!='UAC_' else str(self.uac_to_textflag(x)) for x in attrs]

	def __str__(self):
		t = 'MSADGMSAUser\n'
		t += 'sn: %s\n' % self.sn 
		t += 'cn: %s\n' % self.cn 
		t += 'distinguishedName: %s\n' % self.distinguishedName 
		t += 'name: %s\n' % self.name 
		t += 'primaryGroupID: %s\n' % self.primaryGroupID 
		t += 'sAMAccountName: %s\n' % self.sAMAccountName 
		t += 'accountExpires: %s\n' % self.accountExpires 
		t += 'badPasswordTime: %s\n' % self.badPasswordTime 
		t += 'lastLogoff: %s\n' % self.lastLogoff 
		t += 'lastLogon: %s\n' % self.lastLogon 
		t += 'lastLogonTimestamp: %s\n' % self.lastLogonTimestamp 
		t += 'pwdLastSet: %s\n' % self.pwdLastSet
		t += 'whenChanged: %s\n' % self.whenChanged
		t += 'whenCreated: %s\n' % self.whenCreated 
		t += 'objectGUID: %s\n' % self.objectGUID 
		t += 'objectSid: %s\n' % self.objectSid 
		t += 'badPwdCount: %s\n' % self.badPwdCount
		t += 'logonCount: %s\n' % self.logonCount
		t += 'sAMAccountType: %s\n' % self.sAMAccountType
		t += 'userAccountControl: %s\n' % self.userAccountControl
		t += 'dNSHostName %s\n' % self.dNSHostName
		t += 'msDS-SupportedEncryptionTypes: %s\n' % self.msDS_SupportedEncryptionTypes
		t += 'msDS-ManagedPasswordId: %s\n' % self.msDS_ManagedPasswordId
		t += 'msDS-ManagedPasswordInterval: %s\n' % self.msDS_ManagedPasswordInterval
		t += 'msDS-GroupMSAMembership: %s\n' % self.msDS_GroupMSAMembership
		t += 'msDS-ManagedPassword: %s\n' % self.msDS_ManagedPassword
		return t 
