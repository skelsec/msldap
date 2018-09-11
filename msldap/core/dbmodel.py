import hashlib
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from datetime import datetime, timedelta, timezone
from .common import *
from . import logger

Basemodel = declarative_base()

def create_db(connection, verbosity = 0):
	logger.info('Creating database %s' % connection)
	engine = create_engine(connection, echo=True if verbosity > 1 else False) #'sqlite:///dump.db'	
	Basemodel.metadata.create_all(engine)
	logger.info('Done creating database %s' % connection)

def get_session(connection, verbosity = 0):
	logger.debug('Connecting to DB')
	engine = create_engine(connection, echo=True if verbosity > 1 else False) #'sqlite:///dump.db'	
	logger.debug('Creating session')
	# create a configured "Session" class
	Session = sessionmaker(bind=engine)
	# create a Session
	return Session()

class Project(Basemodel):
	__tablename__ = 'projects'

	id = Column(Integer, primary_key=True)
	name = Column(String)
	created_at = Column(DateTime, default=datetime.utcnow)
	cmd = Column(String)

	ads = relationship("MSADInfo", back_populates="project")

	def __init__(self, name, cmd):
		self.name = name
		self.cmd = cmd


class MSADInfo(Basemodel):
	__tablename__ = 'ads'
	
	ATTRS = [ 	'auditingPolicy', 'creationTime', 'dc', 'distinguishedName', 
				'forceLogoff', 'instanceType', 'lockoutDuration', 'lockOutObservationWindow', 
				'lockoutThreshold', 'masteredBy', 'maxPwdAge', 'minPwdAge', 'minPwdLength', 
				'name', 'nextRid', 'nTSecurityDescriptor', 'objectCategory', 'objectClass', 
				'objectGUID', 'objectSid', 'pwdHistoryLength', 
				'pwdProperties', 'serverState', 'systemFlags', 'uASCompat', 'uSNChanged', 
				'uSNCreated', 'whenChanged', 'whenCreated'
			]
	
	id = Column(Integer, primary_key=True)
	project_id = Column(Integer, ForeignKey('projects.id'))
	project = relationship("Project", back_populates="ads")
	auditingPolicy = Column(String)
	creationTime = Column(DateTime)
	dc = Column(String)
	distinguishedName = Column(String)
	forceLogoff = Column(Integer)
	instanceType = Column(Integer)
	lockoutDuration = Column(Integer)
	lockOutObservationWindow = Column(Integer)
	lockoutThreshold = Column(Integer)
	masteredBy = Column(String)
	maxPwdAge = Column(Integer)
	minPwdAge = Column(Integer)
	minPwdLength = Column(Integer)
	name = Column(String)
	nextRid = Column(Integer)
	nTSecurityDescriptor = Column(String)
	objectCategory = Column(String)
	objectClass = Column(String)
	objectGUID = Column(String)
	objectSid = Column(String)
	pwdHistoryLength = Column(Integer)
	pwdProperties = Column(Integer)
	serverState = Column(Integer)
	systemFlags = Column(Integer)
	uASCompat = Column(Integer)
	uSNChanged = Column(Integer)
	uSNCreated = Column(Integer)
	whenChanged = Column(DateTime)
	whenCreated = Column(DateTime)

	users = relationship("MSADUser", back_populates="ad")

	def from_ldap(entry):
		adi = MSADInfo()
		adi.auditingPolicy = s(entry['attributes'].get('auditingPolicy')) #dunno
		adi.creationTime = s(entry['attributes'].get('creationTime')) #datetime
		adi.dc = s(entry['attributes'].get('dc')) #str
		adi.distinguishedName = s(entry['attributes'].get('distinguishedName')) #string
		adi.forceLogoff = s(entry['attributes'].get('forceLogoff')) #int
		adi.instanceType = s(entry['attributes'].get('instanceType')) #int
		adi.lockoutDuration = s(entry['attributes'].get('lockoutDuration')) #int
		adi.lockOutObservationWindow = s(entry['attributes'].get('lockOutObservationWindow')) #int
		adi.lockoutThreshold = s(entry['attributes'].get('lockoutThreshold')) #int
		adi.masteredBy = s(entry['attributes'].get('masteredBy')) #str
		adi.maxPwdAge = s(entry['attributes'].get('maxPwdAge')) #int
		adi.minPwdAge = s(entry['attributes'].get('minPwdAge')) #int
		adi.minPwdLength = s(entry['attributes'].get('minPwdLength')) #int
		adi.name = s(entry['attributes'].get('name')) #str
		adi.nextRid = s(entry['attributes'].get('nextRid')) #int
		adi.nTSecurityDescriptor = s(entry['attributes'].get('nTSecurityDescriptor')) #str
		adi.objectCategory = s(entry['attributes'].get('objectCategory')) #str
		adi.objectClass = s(entry['attributes'].get('objectClass')) #str
		adi.objectGUID = s(entry['attributes'].get('objectGUID')) #str
		adi.objectSid = s(entry['attributes'].get('objectSid')) #str
		adi.pwdHistoryLength = s(entry['attributes'].get('pwdHistoryLength')) #int
		adi.pwdProperties = s(entry['attributes'].get('pwdProperties')) #int
		adi.serverState = s(entry['attributes'].get('serverState')) #int
		adi.systemFlags = s(entry['attributes'].get('systemFlags')) #int
		adi.uASCompat = s(entry['attributes'].get('uASCompat')) #int
		adi.uSNChanged = s(entry['attributes'].get('uSNChanged')) #int
		adi.uSNCreated = s(entry['attributes'].get('uSNCreated')) #int
		adi.whenChanged = s(entry['attributes'].get('whenChanged')) #datetime
		adi.whenCreated = s(entry['attributes'].get('whenCreated')) #datetime

		return adi

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
		return t 


class MSADUser(Basemodel):
	__tablename__ = 'users'
	
	# this part is for polling the LDAP
	ATTRS = [ 	'accountExpires', 'badPasswordTime', 'badPwdCount', 'cn', 'codePage', 
				'countryCode', 'displayName', 'distinguishedName', 'givenName', 'initials', 
				'lastLogoff', 'lastLogon', 'lastLogonTimestamp', 'logonCount', 'name', 
				'objectCategory', 'objectClass', 'objectGUID', 'objectSid', 'primaryGroupID', 
				'pwdLastSet', 'sAMAccountName', 'sAMAccountType', 'sn', 'userAccountControl', 
				'userPrincipalName', 'whenChanged', 'whenCreated','memberOf','member', 'servicePrincipalName']

	# this part is for TSV representation
	TSV_ATTRS = [  	'sAMAccountName', 'userPrincipalName' ,'canLogon', 'badPasswordTime', 
					'badPwdCount', 'when_pw_change', 'when_pw_expires', 'pwdLastSet', 'lastLogonTimestamp',
					'whenCreated', 'whenChanged', 'member', 'memberOf', 'servicePrincipalName', 
					'objectSid', 'cn', 'UAC_SCRIPT', 'UAC_ACCOUNTDISABLE', 'UAC_LOCKOUT', 'UAC_PASSWD_NOTREQD', 
					'UAC_PASSWD_CANT_CHANGE', 'UAC_ENCRYPTED_TEXT_PASSWORD_ALLOWED', 'UAC_DONT_EXPIRE_PASSWD', 'UAC_USE_DES_KEY_ONLY', 
					'UAC_DONT_REQUIRE_PREAUTH', 'UAC_PASSWORD_EXPIRED'

				]

	# Now for the attributes
	id = Column(Integer, primary_key=True)
	ad_id = Column(Integer, ForeignKey('ads.id'))
	ad = relationship("MSADInfo", back_populates="users")
	sn = Column(String)
	cn = Column(String)
	distinguishedName = Column(String)
	initials = Column(String)
	givenName = Column(String)
	displayName = Column(String)
	name = Column(String)
	objectCategory = Column(String)
	objectClass = Column(String)
	objectGUID = Column(String)
	objectSid = Column(String, index=True)
	primaryGroupID = Column(String)
	sAMAccountName = Column(String, index=True)
	userPrincipalName = Column(String)
	servicePrincipalName = Column(String)
	## groups
	memberOf = Column(String) #list, should be extra table
	member = Column(String) #list, should be extra table
	## times
	accountExpires = Column(DateTime)
	badPasswordTime = Column(DateTime)
	lastLogoff = Column(DateTime)
	lastLogon = Column(DateTime)
	lastLogonTimestamp = Column(DateTime)
	pwdLastSet = Column(DateTime)
	whenChanged = Column(DateTime)
	whenCreated = Column(DateTime)
	## security
	badPwdCount = Column(Integer)
	logonCount = Column(Integer)
	sAMAccountType = Column(Integer)
	userAccountControl = Column(Integer)
	
	## other
	codePage = Column(Integer)
	countryCode = Column(Integer)
	
	## calculated properties
	when_pw_change = Column(DateTime)
	when_pw_expires = Column(DateTime)
	must_change_pw = Column(DateTime)
	canLogon = Column(Boolean)

	credential = relationship("Credential", back_populates="user")

	


	# https://msdn.microsoft.com/en-us/library/cc245739.aspx
	def calc_PasswordMustChange(self):
		# Crtieria 1
		flags = [MSLDAP_UAC.DONT_EXPIRE_PASSWD, MSLDAP_UAC.SMARTCARD_REQUIRED, MSLDAP_UAC.INTERDOMAIN_TRUST_ACCOUNT, MSLDAP_UAC.WORKSTATION_TRUST_ACCOUNT, MSLDAP_UAC.SERVER_TRUST_ACCOUNT]
		for flag in flags:
			if flag & self.userAccountControl:
				return datetime(3000,1,1) #never

		#criteria 2
		if self.pwdLastSet == 0:
			return datetime(1601,1,1)

		if (self.when_pw_expires - datetime.now()).total_seconds() > 0:
			return datetime(3000,1,1) #never

		return self.pwdLastSet.replace(tzinfo=None)


	# https://msdn.microsoft.com/en-us/library/cc223991.aspx
	def calc_CanLogon(self):
		flags = [MSLDAP_UAC.ACCOUNTDISABLE, MSLDAP_UAC.LOCKOUT, MSLDAP_UAC.SMARTCARD_REQUIRED, MSLDAP_UAC.INTERDOMAIN_TRUST_ACCOUNT, MSLDAP_UAC.WORKSTATION_TRUST_ACCOUNT, MSLDAP_UAC.SERVER_TRUST_ACCOUNT]
		for flag in flags:
			if flag & self.userAccountControl:
				return False

		if (self.accountExpires.replace(tzinfo=None) - datetime.now()).total_seconds() < 0:
			return False

		#
		# TODO: logonHours check!
		#
		
		if self.must_change_pw == datetime(1601,1,1):
			#can logon, but must change the password!
			return True

		if (self.must_change_pw - datetime.now()).total_seconds() < 0:
			return False

		return True


	def from_ldap(entry, adinfo = None):
		adi = MSADUser()
		adi.sn = s(entry['attributes'].get('sn') )
		adi.cn = s(entry['attributes'].get('cn') )
		adi.distinguishedName = s(entry['attributes'].get('distinguishedName'))
		adi.initials = s(entry['attributes'].get('initials'))
		adi.givenName = s(entry['attributes'].get('givenName'))
		adi.displayName = s(entry['attributes'].get('displayName'))
		adi.name = s(entry['attributes'].get('name'))
		adi.objectCategory = s(entry['attributes'].get('objectCategory'))
		adi.objectClass = s(entry['attributes'].get('objectClass'))
		adi.objectGUID = s(entry['attributes'].get('objectGUID'))
		adi.objectSid = s(entry['attributes'].get('objectSid'))
		adi.primaryGroupID = s(entry['attributes'].get('primaryGroupID'))
		adi.sAMAccountName = s(entry['attributes'].get('sAMAccountName'))
		adi.userPrincipalName = s(entry['attributes'].get('userPrincipalName'))
		adi.servicePrincipalName = s(entry['attributes'].get('servicePrincipalName'))
		adi.memberOf = s(entry['attributes'].get('memberOf'))
		adi.member = s(entry['attributes'].get('member'))
		adi.accountExpires = s(entry['attributes'].get('accountExpires'))
		adi.badPasswordTime = s(entry['attributes'].get('badPasswordTime'))
		adi.lastLogoff = s(entry['attributes'].get('lastLogoff'))
		adi.lastLogon = s(entry['attributes'].get('lastLogon'))
		adi.lastLogonTimestamp = s(entry['attributes'].get('lastLogonTimestamp'))
		adi.pwdLastSet = s(entry['attributes'].get('pwdLastSet'))
		adi.whenChanged = s(entry['attributes'].get('whenChanged'))
		adi.whenCreated = s(entry['attributes'].get('whenCreated'))
		adi.badPwdCount = s(entry['attributes'].get('badPwdCount'))
		adi.logonCount = s(entry['attributes'].get('logonCount'))
		adi.sAMAccountType = s(entry['attributes'].get('sAMAccountType'))
		adi.codePage = s(entry['attributes'].get('codePage'))
		adi.countryCode = s(entry['attributes'].get('countryCode'))
		
		temp = entry['attributes'].get('userAccountControl')
		if temp:
			adi.userAccountControl = MSLDAP_UAC(temp)

			if adinfo:
				adi.when_pw_change = (adi.pwdLastSet - timedelta(seconds = adinfo.minPwdAge/10000000)).replace(tzinfo=None)
				adi.when_pw_expires = (adi.pwdLastSet - timedelta(seconds = adinfo.maxPwdAge/10000000)).replace(tzinfo=None)
				adi.must_change_pw = adi.calc_PasswordMustChange() #datetime
				if adi.sAMAccountName[-1] != '$':
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
		t['canLogon'] = vn(self.canLogon)
		return t

	def uac_to_textflag(self, attr_s):
		attr = getattr(MSLDAP_UAC, attr_s[4:])
		if self.userAccountControl & attr:
			return True
		return False

	def get_row(self, attrs):
		t = self.to_dict()
		return [t.get(x) if x[:4]!='UAC_' else self.uac_to_textflag(x) for x in attrs]

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
		t += 'canLogon: %s\n' % self.canLogon

		return t

class Credential(Basemodel):
	__tablename__ = 'credentials'

	id = Column(Integer, primary_key=True)
	user_id = Column(Integer, ForeignKey('users.id'))
	user = relationship("MSADUser", back_populates="credential")
	nt_hash = Column(String, index=True)
	lm_hash = Column(String, index=True)
	history_no = Column(Integer, index=True)

	@staticmethod
	def from_impacket(data):
		"""
		Remember that this doesnt populate the foreign keys!!! You'll have to do it separately!
		"""
		creds = []
		for line in data:
			cred = Credential()
			userdomainhist, flags, lm_hash, nt_hash, *t = line.split(':')
			#parsing history
			m = userdomainhist.find('_history')
			history_no = None
			if m != -1:
				history_no = int(userdomainhist.split('_history')[1])
				userdomainhist = userdomainhist.split('_history')[0]
			m = userdomainhist.find('\\')
			domain = '<LOCAL>'
			sAMAccountName = userdomainhist
			if m != -1:
				domain = userdomainhist.split('\\')[0]
				sAMAccountName = userdomainhist.split('\\')[1]
			cred.nt_hash = nt_hash
			cred.lm_hash = lm_hash
			cred.history_no = history_no
			creds.append((domain, sAMAccountName ,cred))

		return creds

class HashEntry(Basemodel):
	__tablename__ = 'hashes'
	
	id = Column(Integer, primary_key=True)
	nt_hash = Column(String, index = True)
	lm_hash = Column(String, index = True)
	plaintext = Column(String, index = True)

	def __init__(self, plaintext, nt_hash = None, lm_hash = None):
		self.plaintext = plaintext
		self.nt_hash = nt_hash
		self.lm_hash = lm_hash


	@staticmethod
	def from_plaintext(plaintext):
		nt_hash = hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest()
		return HashEntry(plaintext, nt_hash)

	@staticmethod
	def from_potfile(data, hashtype = HashType.NT):
		entries = []
		cnt = 0
		for line in data:
			cnt += 1
			line = line.strip()
			m = line.find(':')
			if m == -1:
				logging.info('Incorrect hashcat potfile line on lineno %d' % cnt)
				continue
			plaintext = line[m+1:]
			if hashtype == HashType.NT:
				nt_hash = line[:m]
				entries.append(HashEntry(plaintext, nt_hash = nt_hash))
			elif hashtype == HashType.NT:
				lm_hash = line[:m]
				entries.append(HashEntry(plaintext, lm_hash = lm_hash))
			else:
				raise Exception('Unsupported hash format!')
				continue	
			
			
		return entries


