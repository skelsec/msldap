
from msldap.protocol.messages import resultCode


LDAPResultCodeLookup ={
	0  : 'success',
	1  : 'operationsError',
	2  : 'protocolError',
	3  : 'timeLimitExceeded',
	4  : 'sizeLimitExceeded',
	5  : 'compareFalse',
	6  : 'compareTrue',
	7  : 'authMethodNotSupported',
	8  : 'strongerAuthRequired',
	10 : 'referral',
	11 : 'adminLimitExceeded',
	12 : 'unavailableCriticalExtension',
	13 : 'confidentialityRequired',
	14 : 'saslBindInProgress',
	16 : 'noSuchAttribute',
	17 : 'undefinedAttributeType',
	18 : 'inappropriateMatching',
	19 : 'constraintViolation',
	20 : 'attributeOrValueExists',
	21 : 'invalidAttributeSyntax',
	32 : 'noSuchObject',
	33 : 'aliasProblem',
	34 : 'invalidDNSyntax',
	36 : 'aliasDereferencingProblem',
	48 : 'inappropriateAuthentication',
	49 : 'invalidCredentials',
	50 : 'insufficientAccessRights',
	51 : 'busy',
	52 : 'unavailable',
	53 : 'unwillingToPerform',
	54 : 'loopDetect',
	64 : 'namingViolation',
	65 : 'objectClassViolation',
	66 : 'notAllowedOnNonLeaf',
	67 : 'notAllowedOnRDN',
	68 : 'entryAlreadyExists',
	69 : 'objectClassModsProhibited',
	71 : 'affectsMultipleDSAs',
	80 : 'other',
}
LDAPResultCodeLookup_inv = {v: k for k, v in LDAPResultCodeLookup.items()}

class LDAPServerException(Exception):
	def __init__(self, resultname, diagnostic_message, message = None):
		self.resultcode = LDAPResultCodeLookup_inv[resultname]
		self.resultname = resultname
		self.diagnostic_message = diagnostic_message
		self.message = message
		if self.message is None:
			self.message = 'LDAP server sent error! Result code: "%s" Reason: "%s"' % (self.resultcode, self.diagnostic_message)
		super().__init__(self.message)

class LDAPBindException(LDAPServerException):
	def __init__(self, resultcode, diagnostic_message):
		message = 'LDAP Bind failed! Result code: "%s" Reason: "%s"' % (resultcode, diagnostic_message)
		super().__init__(resultcode, diagnostic_message, message)

class LDAPAddException(LDAPServerException):
	def __init__(self, dn, resultcode, diagnostic_message):
		self.dn = dn
		message = 'LDAP Add operation failed on DN %s! Result code: "%s" Reason: "%s"' % (self.dn, resultcode, diagnostic_message)
		super().__init__(resultcode, diagnostic_message, message)

class LDAPModifyException(LDAPServerException):
	def __init__(self, dn, resultcode, diagnostic_message):
		self.dn = dn
		message = 'LDAP Modify operation failed on DN %s! Result code: "%s" Reason: "%s"' % (self.dn, resultcode, diagnostic_message)
		super().__init__(resultcode, diagnostic_message, message)

class LDAPDeleteException(LDAPServerException):
	def __init__(self, dn, resultcode, diagnostic_message):
		self.dn = dn
		message = 'LDAP Delete operation failed on DN %s! Result code: "%s" Reason: "%s"' % (self.dn, resultcode, diagnostic_message)
		super().__init__(resultcode, diagnostic_message, message)
