#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import datetime
import base64
from msldap.ldap_objects.common import MSLDAP_UAC, vn
from msldap.commons.utils import bh_dt_convert

MSADMachine_ATTRS = [
	'accountExpires', 'badPasswordTime', 'badPwdCount', 'cn', 'description', 'codePage', 
	'countryCode', 'displayName', 'distinguishedName', 'dNSHostName',
	'instanceType', 'isCriticalSystemObject','lastLogoff', 'lastLogon', 
	'lastLogonTimestamp', 'logonCount', 'localPolicyFlags',	'msDS-SupportedEncryptionTypes',
	'name', 'objectCategory', 'objectClass', 'objectGUID', 'objectSid', 
	'operatingSystem', 'operatingSystemVersion','primaryGroupID', 
	'pwdLastSet', 'sAMAccountName', 'sAMAccountType', 'sn', 'userAccountControl', 
	'whenChanged', 'whenCreated', 'servicePrincipalName','msDS-AllowedToDelegateTo',
	'msDS-AllowedToActOnBehalfOfOtherIdentity', 'operatingSystemServicePack', 'isDeleted',
	'ms-Mcs-AdmPwdExpirationTime', 'sIDHistory'
]

MSADMachine_TSV_ATTRS = [
	'sAMAccountName', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion','operatingSystemServicePack', 
	'badPasswordTime', 'badPwdCount', 'pwdLastSet', 'lastLogonTimestamp', 'whenCreated', 'whenChanged', 'servicePrincipalName', 
	'objectSid', 'cn', 'description', 'UAC_SCRIPT', 'UAC_ACCOUNTDISABLE', 'UAC_LOCKOUT', 'UAC_PASSWD_NOTREQD', 
	'UAC_PASSWD_CANT_CHANGE', 'UAC_ENCRYPTED_TEXT_PASSWORD_ALLOWED', 'UAC_DONT_EXPIRE_PASSWD', 'UAC_USE_DES_KEY_ONLY', 
	'UAC_DONT_REQUIRE_PREAUTH', 'UAC_PASSWORD_EXPIRED'
]

class MSADMachine:
	def __init__(self):
		self.sn = None #str
		self.cn = None #str
		self.distinguishedName = None #dn
		self.accountExpires = None
		self.badPasswordTime = None
		self.badPwdCount = None
		self.codePage = None
		self.countryCode = None
		self.displayName = None
		self.dNSHostName = None
		self.description = None
		self.instanceType = None
		self.isCriticalSystemObject = None
		self.lastLogoff = None
		self.lastLogon = None
		self.lastLogonTimestamp = None
		self.logonCount = None
		self.localPolicyFlags = None
		self.supported_enc_types = None
		self.name = None
		self.nTSecurityDescriptor = None
		self.objectCategory = None
		self.objectClass = None
		self.objectGUID = None
		self.objectSid = None
		self.operatingSystem = None
		self.operatingSystemVersion = None
		self.primaryGroupID = None
		self.pwdLastSet = None
		self.sAMAccountName = None
		self.sAMAccountType = None
		self.userAccountControl = None
		self.whenChanged = None
		self.whenCreated = None
		self.servicePrincipalName = None
		self.allowedtodelegateto = None
		self.allowedtoactonbehalfofotheridentity = None
		self.operatingSystemServicePack = None
		self.isDeleted = None
		self.ms_Mcs_AdmPwdExpirationTime = None
		self.sIDHistory = None

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
		adi = MSADMachine()
		adi.sn = entry['attributes'].get('sn') 
		adi.cn = entry['attributes'].get('cn') 
		adi.distinguishedName = entry['attributes'].get('distinguishedName')
		adi.accountExpires = entry['attributes'].get('accountExpires')
		adi.badPasswordTime = entry['attributes'].get('badPasswordTime')
		adi.badPwdCount = entry['attributes'].get('badPwdCount')
		adi.codePage = entry['attributes'].get('codePage')
		adi.countryCode = entry['attributes'].get('countryCode')
		adi.description = entry['attributes'].get('description')
		adi.displayName = entry['attributes'].get('displayName')
		adi.dNSHostName = entry['attributes'].get('dNSHostName')
		adi.instanceType = entry['attributes'].get('instanceType')
		adi.isCriticalSystemObject = entry['attributes'].get('isCriticalSystemObject')
		adi.lastLogoff = entry['attributes'].get('lastLogoff')
		adi.lastLogon = entry['attributes'].get('lastLogon')
		adi.lastLogonTimestamp = entry['attributes'].get('lastLogonTimestamp')
		adi.logonCount = entry['attributes'].get('logonCount')
		adi.localPolicyFlags = entry['attributes'].get('localPolicyFlags')
		adi.supported_enc_types = entry['attributes'].get('msDS-SupportedEncryptionTypes')
		adi.name = entry['attributes'].get('name')
		adi.objectCategory = entry['attributes'].get('objectCategory')
		adi.objectClass = entry['attributes'].get('objectClass')
		adi.objectGUID = entry['attributes'].get('objectGUID')
		adi.objectSid = entry['attributes'].get('objectSid')
		adi.operatingSystem = entry['attributes'].get('operatingSystem')
		adi.operatingSystemVersion = entry['attributes'].get('operatingSystemVersion')
		adi.primaryGroupID = entry['attributes'].get('primaryGroupID')
		adi.pwdLastSet = entry['attributes'].get('pwdLastSet')
		adi.sAMAccountName = entry['attributes'].get('sAMAccountName')
		adi.sAMAccountType = entry['attributes'].get('sAMAccountType')
		adi.whenChanged = entry['attributes'].get('whenChanged')
		adi.whenCreated = entry['attributes'].get('whenCreated')
		adi.servicePrincipalName = entry['attributes'].get('servicePrincipalName')
		adi.operatingSystemServicePack = entry['attributes'].get('operatingSystemServicePack')
		adi.isDeleted = entry['attributes'].get('isDeleted')
		adi.ms_Mcs_AdmPwdExpirationTime = entry['attributes'].get('ms-Mcs-AdmPwdExpirationTime')
		adi.sIDHistory = entry['attributes'].get('sIDHistory')
		
		adi.allowedtodelegateto = entry['attributes'].get('msDS-AllowedToDelegateTo')
		adi.allowedtoactonbehalfofotheridentity = entry['attributes'].get('msDS-AllowedToActOnBehalfOfOtherIdentity')

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
		t['accountExpires'] = vn(self.accountExpires)
		t['badPasswordTime'] = vn(self.badPasswordTime)
		t['badPwdCount'] = vn(self.badPwdCount)
		t['codePage'] = vn(self.codePage)
		t['countryCode'] = vn(self.countryCode)
		t['description'] = vn(self.description)
		t['displayName'] = vn(self.displayName)
		t['dNSHostName'] = vn(self.dNSHostName)
		t['instanceType'] = vn(self.instanceType)
		t['isCriticalSystemObject'] = vn(self.isCriticalSystemObject)
		t['lastLogoff'] = vn(self.lastLogoff)
		t['lastLogon'] = vn(self.lastLogon)
		t['lastLogonTimestamp'] = vn(self.lastLogonTimestamp)
		t['logonCount'] = vn(self.logonCount)
		t['localPolicyFlags'] = vn(self.localPolicyFlags)
		t['supported_enc_types'] = vn(self.supported_enc_types)
		t['name'] = vn(self.name)
		t['objectCategory'] = vn(self.objectCategory)
		t['objectClass'] = vn(self.objectClass)
		t['objectGUID'] = vn(self.objectGUID)
		t['objectSid'] = vn(self.objectSid)
		t['operatingSystem'] = vn(self.operatingSystem)
		t['operatingSystemVersion'] = vn(self.operatingSystemVersion)
		t['primaryGroupID'] = vn(self.primaryGroupID)
		t['pwdLastSet'] = vn(self.pwdLastSet)
		t['sAMAccountName'] = vn(self.sAMAccountName)
		t['sAMAccountType'] = vn(self.sAMAccountType)
		t['whenChanged'] = vn(self.whenChanged)
		t['whenCreated'] = vn(self.whenCreated)
		t['servicePrincipalName'] = vn(self.servicePrincipalName)
		t['userAccountControl'] = vn(self.userAccountControl)
		t['operatingSystemServicePack'] = vn(self.operatingSystemServicePack)
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
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t
	
	def to_bh(self, domain):
		uac = self.userAccountControl
		if uac is None:
			uac = MSLDAP_UAC(0)
		op = self.operatingSystem
		if self.operatingSystem is not None:
			if self.operatingSystemServicePack is not None:
				op = self.operatingSystem + ' ' + self.operatingSystemServicePack

		sidhistory = []
		if self.sIDHistory is not None:
			for sid in self.sIDHistory:
				sidhistory.append(str(sid))
		
		actonbehalf = self.allowedtoactonbehalfofotheridentity
		if actonbehalf is not None:
			actonbehalf = base64.b64encode(actonbehalf).decode()

		alloweddeleg = self.allowedtodelegateto
		if alloweddeleg is None:
			alloweddeleg = []
		return {
			'_allowedtoactonbehalfofotheridentity' : actonbehalf,
			'_dns' : self.dNSHostName,

			'Aces' : [], #Post processing
			'AllowedToDelegate' : [], #Post processing
			'AllowedToAct' : [], #Post processing
			'ObjectIdentifier' : self.objectSid,
			'PrimaryGroupSID' : str(self.objectSid).rsplit('-',1)[0] + '-' + str(self.primaryGroupID),
			"SPNTargets": [], #this seems to be always empty
			"HasSIDHistory": [], #this seems to be always empty
			"IsDeleted": bool(self.isDeleted),
			"IsACLProtected": False , # Post processing
			"Status": None, # no idea what this is
			"DumpSMSAPassword" : [],
			'Properties' : {
				'name' : '%s@%s' % (self.sAMAccountName.upper(), domain.upper()),
				'domain' : domain,
				'domainsid' : str(self.objectSid).rsplit('-',1)[0] , 
				'distinguishedname' : str(self.distinguishedName).upper(), 
				'unconstraineddelegation' : self.uac_to_textflag('UAC_TRUSTED_FOR_DELEGATION'),
				'enabled' : MSLDAP_UAC.ACCOUNTDISABLE not in uac,
				'trustedtoauth' : MSLDAP_UAC.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION in uac, 
				'samaccountname' : self.sAMAccountName ,
				'haslaps' : self.ms_Mcs_AdmPwdExpirationTime is not None,
				'lastlogon' : bh_dt_convert(self.lastLogon),
				'lastlogontimestamp' : bh_dt_convert(self.lastLogonTimestamp),
				'whencreated' : bh_dt_convert(self.whenCreated),
				'serviceprincipalnames' : self.servicePrincipalName,
				'description' : self.description ,
				'operatingsystem' : op,
				'sidhistory' : sidhistory,
				'allowedtodelegate' : alloweddeleg,
			},
			'LocalAdmins': {
                'Collected': False,
                'FailureReason': None,
                'Results': [],
            },
            'PSRemoteUsers': {
                'Collected': False,
                'FailureReason': None,
                'Results': [],
            },
			'RemoteDesktopUsers': {
                'Collected': False,
                'FailureReason': None,
                'Results': [],
            },
            'DcomUsers': {
                'Collected': False,
                'FailureReason': None,
                'Results': [],
            },
			'Sessions': {
                'Collected': False,
                'FailureReason': None,
                'Results': [],
            },
            'PrivilegedSessions': {
                'Collected': False,
                'FailureReason': None,
                'Results': [],
            },
            'RegistrySessions': {
                'Collected': False,
                'FailureReason': None,
                'Results': [],
            },
		}