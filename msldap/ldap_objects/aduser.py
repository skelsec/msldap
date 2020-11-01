#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import datetime #, timedelta, timezone
from msldap.ldap_objects.common import MSLDAP_UAC, vn

MSADUser_ATTRS = [ 	
	'accountExpires', 'badPasswordTime', 'badPwdCount', 'cn', 'codePage', 
	'countryCode', 'displayName', 'distinguishedName', 'givenName', 'initials', 
	'lastLogoff', 'lastLogon', 'lastLogonTimestamp', 'logonCount', 'name', 'description',
	'objectCategory', 'objectClass', 'objectGUID', 'objectSid', 'primaryGroupID', 
	'pwdLastSet', 'sAMAccountName', 'sAMAccountType', 'sn', 'userAccountControl', 
	'userPrincipalName', 'whenChanged', 'whenCreated','memberOf','member', 'servicePrincipalName',
	'msDS-AllowedToDelegateTo', 'adminCount'
]
MSADUser_TSV_ATTRS = [
	'sAMAccountName', 'userPrincipalName' ,'canLogon', 'badPasswordTime', 'description',
	'badPwdCount', 'when_pw_change', 'when_pw_expires', 'pwdLastSet', 'lastLogonTimestamp',
	'whenCreated', 'whenChanged', 'member', 'memberOf', 'servicePrincipalName', 
	'objectSid', 'cn', 'UAC_SCRIPT', 'UAC_ACCOUNTDISABLE', 'UAC_LOCKOUT', 'UAC_PASSWD_NOTREQD', 
	'UAC_PASSWD_CANT_CHANGE', 'UAC_ENCRYPTED_TEXT_PASSWORD_ALLOWED', 'UAC_DONT_EXPIRE_PASSWD', 
	'UAC_USE_DES_KEY_ONLY', 'UAC_DONT_REQUIRE_PREAUTH', 'UAC_PASSWORD_EXPIRED', 'adminCount'
]

class MSADUser:
	def __init__(self):
		## ID
		self.sn = None #str
		self.cn = None #str
		self.distinguishedName = None #dn

		self.initials = None #str
		self.givenName = None #str
		self.displayName = None #str
		self.name = None #str
		self.description = None

		self.objectCategory = None #dn
		self.objectClass = None #str
		self.objectGUID = None #uid
		self.objectSid = None #str
		self.primaryGroupID = None #uid
		self.sAMAccountName = None #str
		self.userPrincipalName = None #str
		self.servicePrincipalName = None #str

		## groups
		self.memberOf = None #list
		self.member = None #list

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
		self.allowedtodelegateto = None
		self.admincount = None

		
		## other
		self.codePage = None #int
		self.countryCode = None #int
		
		## calculated properties
		self.when_pw_change = None #datetime
		self.when_pw_expires = None #datetime
		self.must_change_pw = None #datetime
		self.canLogon = None #bool

	# https://msdn.microsoft.com/en-us/library/cc245739.aspx
	def calc_PasswordMustChange(self, adinfo):
		# Crtieria 1
		flags = [MSLDAP_UAC.DONT_EXPIRE_PASSWD, MSLDAP_UAC.SMARTCARD_REQUIRED, MSLDAP_UAC.INTERDOMAIN_TRUST_ACCOUNT, MSLDAP_UAC.WORKSTATION_TRUST_ACCOUNT, MSLDAP_UAC.SERVER_TRUST_ACCOUNT]
		for flag in flags:
			if flag & self.userAccountControl:
				return datetime.datetime.max #never

		#criteria 2
		if self.pwdLastSet == datetime.timedelta():
			return datetime.datetime.min

		if adinfo.maxPwdAge == datetime.timedelta(): #empty timedelta
			return datetime.datetime.max #never

		if adinfo.maxPwdAge.days < -3650: #this is needed, because some ADs have mawPwdAge set for a huge number BUT not to the minimum
			return datetime.datetime.max #never

		return (self.pwdLastSet - adinfo.maxPwdAge).replace(tzinfo=None)


	# https://msdn.microsoft.com/en-us/library/cc223991.aspx
	def calc_CanLogon(self):
		flags = [MSLDAP_UAC.ACCOUNTDISABLE, MSLDAP_UAC.LOCKOUT, MSLDAP_UAC.SMARTCARD_REQUIRED, MSLDAP_UAC.INTERDOMAIN_TRUST_ACCOUNT, MSLDAP_UAC.WORKSTATION_TRUST_ACCOUNT, MSLDAP_UAC.SERVER_TRUST_ACCOUNT]
		for flag in flags:
			if flag & self.userAccountControl:
				return False
		
		if (not (MSLDAP_UAC.DONT_EXPIRE_PASSWD & self.userAccountControl)) and (self.accountExpires.replace(tzinfo=None) - datetime.datetime.now()).total_seconds() < 0:
			return False

		#
		# TODO: logonHours check!
		#
		
		if self.must_change_pw == datetime.datetime.min:
			#can logon, but must change the password!
			return True

		if (self.must_change_pw - datetime.datetime.now()).total_seconds() < 0:
			return False

		return True

	@staticmethod
	def from_ldap(entry, adinfo = None):
		adi = MSADUser()
		adi.sn = entry['attributes'].get('sn') 
		adi.cn = entry['attributes'].get('cn') 
		adi.distinguishedName = entry['attributes'].get('distinguishedName')
		adi.description = entry['attributes'].get('description')
		adi.initials = entry['attributes'].get('initials')
		adi.givenName = entry['attributes'].get('givenName')
		adi.displayName = entry['attributes'].get('displayName')
		adi.name = entry['attributes'].get('name')
		adi.objectCategory = entry['attributes'].get('objectCategory')
		adi.objectClass = entry['attributes'].get('objectClass')
		adi.objectGUID = entry['attributes'].get('objectGUID')
		adi.objectSid = entry['attributes'].get('objectSid')
		adi.primaryGroupID = entry['attributes'].get('primaryGroupID')
		adi.sAMAccountName = entry['attributes'].get('sAMAccountName')
		adi.userPrincipalName = entry['attributes'].get('userPrincipalName')
		adi.servicePrincipalName = entry['attributes'].get('servicePrincipalName')
		adi.memberOf = entry['attributes'].get('memberOf')
		adi.member = entry['attributes'].get('member')
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
		adi.codePage = entry['attributes'].get('codePage')
		adi.countryCode = entry['attributes'].get('countryCode')
		
		adi.allowedtodelegateto = entry['attributes'].get('msDS-AllowedToDelegateTo')
		adi.admincount = entry['attributes'].get('adminCount')
		
		temp = entry['attributes'].get('userAccountControl')
		if temp:
			adi.userAccountControl = MSLDAP_UAC(temp)

			if adinfo:
				adi.when_pw_change = (adi.pwdLastSet - adinfo.minPwdAge).replace(tzinfo=None)
				if adinfo.maxPwdAge.days < -3650: #this is needed, because some ADs have mawPwdAge set for a huge number BUT not to the minimum
					adi.when_pw_expires = datetime.datetime.max
				else:
					adi.when_pw_expires = (adi.pwdLastSet - adinfo.maxPwdAge).replace(tzinfo=None) if adinfo.maxPwdAge != 0 else adi.pwdLastSet
				adi.must_change_pw = adi.calc_PasswordMustChange(adinfo) #datetime
				adi.canLogon = adi.calc_CanLogon() #bool


		return adi

	def to_dict(self):
		t = {}
		t['sn'] = vn(self.sn)
		t['cn'] = vn(self.cn)
		t['distinguishedName'] = vn(self.distinguishedName)
		t['initials'] = vn(self.initials)
		t['givenName'] = vn(self.givenName)
		t['displayName'] = vn(self.displayName)
		t['description'] = vn(self.description)
		t['name'] = vn(self.name)
		t['objectCategory'] = vn(self.objectCategory)
		t['objectClass'] = vn(self.objectClass)
		t['objectGUID'] = vn(self.objectGUID)
		t['objectSid'] = vn(self.objectSid)
		t['primaryGroupID'] = vn(self.primaryGroupID)
		t['sAMAccountName'] = vn(self.sAMAccountName)
		t['userPrincipalName'] = vn(self.userPrincipalName)
		t['servicePrincipalName'] = vn(self.servicePrincipalName)
		t['memberOf'] = vn(self.memberOf)
		t['member'] = vn(self.member)
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
		t['codePage'] = vn(self.codePage)
		t['countryCode'] = vn(self.countryCode)
		t['userAccountControl'] = vn(self.userAccountControl)
		t['when_pw_change'] = vn(self.when_pw_change)
		t['when_pw_expires'] = vn(self.when_pw_expires)
		t['must_change_pw'] = vn(self.must_change_pw)
		t['admincount'] = self.admincount
		t['canLogon'] = vn(self.canLogon)
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
		t = 'MSADUser\n'
		t += 'sn: %s\n' % self.sn 
		t += 'cn: %s\n' % self.cn 
		t += 'distinguishedName: %s\n' % self.distinguishedName 
		t += 'initials: %s\n' % self.initials 
		t += 'displayName: %s\n' % self.displayName 
		t += 'name: %s\n' % self.name 
		t += 'primaryGroupID: %s\n' % self.primaryGroupID 
		t += 'sAMAccountName: %s\n' % self.sAMAccountName 
		t += 'userPrincipalName: %s\n' % self.userPrincipalName 
		t += 'servicePrincipalName: %s\n' % self.servicePrincipalName 
		t += 'memberOf: %s\n' % self.memberOf 
		t += 'member: %s\n' % self.member 
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
		t += 'codePage: %s\n' % self.codePage
		t += 'countryCode: %s\n' % self.countryCode
		t += 'userAccountControl: %s\n' % self.userAccountControl
		t += 'when_pw_change: %s\n' % self.when_pw_change
		t += 'when_pw_expires: %s\n' % self.when_pw_expires
		t += 'must_change_pw: %s\n' % self.must_change_pw
		t += 'admincount: %s\n' % self.admincount
		t += 'canLogon: %s\n' % self.canLogon

		return t 



		

		
		
		
		
		
		
		
		
		
		
		
		
		