import datetime
import re

from winacl.dtyp.sid import SID
from winacl.dtyp.guid import GUID
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from msldap import logger
from msldap.protocol.messages import Attribute, Change, PartialAttribute

MSLDAP_DT_WIN_EPOCH = datetime.datetime(1601, 1, 1)

#this regex and the function that uses it is from ldap3
time_format = re.compile(
        r'''
        ^
        (?P<Year>[0-9]{4})
        (?P<Month>0[1-9]|1[0-2])
        (?P<Day>0[1-9]|[12][0-9]|3[01])
        (?P<Hour>[01][0-9]|2[0-3])
        (?:
          (?P<Minute>[0-5][0-9])
          (?P<Second>[0-5][0-9]|60)?
        )?
        (?:
          [.,]
          (?P<Fraction>[0-9]+)
        )?  
        (?:
          Z
          |
          (?:
            (?P<Offset>[+-])
            (?P<OffHour>[01][0-9]|2[0-3])
            (?P<OffMinute>[0-5][0-9])?
          )
        )
        $
        ''',
        re.VERBOSE
    )

def x2sd(x):
	return SECURITY_DESCRIPTOR.from_bytes(x[0])

def x2sid(x):
	return str(SID.from_bytes(x[0]))

def list_x2sid(x):
	t = []
	for s in x:
		t.append(str(SID.from_bytes(s)))
	return t

def list_bool_one(x):
	x = x[0].decode()
	if x == 'FALSE':
		return False
	return True

def x2guid(x):
	return str(GUID.from_bytes(x[0]))

def list_str(x):
	return [e.decode() for e in x ]

def list_str_enc(x):
	return [e.encode() for e in x ]

def list_int(x):
	return [int(e) for e in x ]

def list_int_enc(x):
	return [str(e).encode() for e in x ]

def list_int_one(x):
	return int(x[0])

def list_int_one_enc(x):
	return [str(x[0]).encode()]

def list_str_one(x):
	return x[0].decode()

def list_str_one_enc(x):
	return [x[0].encode()]

def list_str_one_utf16le_enc(x):
	return [x[0].encode('utf-16-le')]

def list_bytes_one(x):
	return x[0]

def list_bytes_one_enc(x):
	return x

def int2timedelta(x):
	x = int(x[0])
	if x == '-9223372036854775808':
		return datetime.timedelta.max
	return datetime.timedelta(microseconds=(x / 10.))

def int2dt(x):
	x = int(x[0])
	if x == 9223372036854775807:
		return datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)
	
	us = x / 10.
	return (MSLDAP_DT_WIN_EPOCH + datetime.timedelta(microseconds=us)).replace(tzinfo=datetime.timezone.utc)

def ts2dt(x):
	try:
		x = x[0].decode()
		match = time_format.fullmatch(x)
		if match is None:
			return x
		matches = match.groupdict()

		offset = datetime.timedelta(
			hours=int(matches['OffHour'] or 0),
			minutes=int(matches['OffMinute'] or 0)
		)

		if matches['Offset'] == '-':
			offset *= -1

		# Python does not support leap second in datetime (!)
		if matches['Second'] == '60':
			matches['Second'] = '59'

		# According to RFC, fraction may be applied to an Hour/Minute (!)
		fraction = float('0.' + (matches['Fraction'] or '0'))

		if matches['Minute'] is None:
			fraction *= 60
			minute = int(fraction)
			fraction -= minute
		else:
			minute = int(matches['Minute'])

		if matches['Second'] is None:
			fraction *= 60
			second = int(fraction)
			fraction -= second
		else:
			second = int(matches['Second'])

		microseconds = int(fraction * 1000000)

		return datetime.datetime(
			int(matches['Year']),
			int(matches['Month']),
			int(matches['Day']),
			int(matches['Hour']),
			minute,
			second,
			microseconds,
			datetime.timezone(offset),
		)
	except Exception:  # exceptions should be investigated, anyway the formatter return the raw_value
		pass
	return x

def list_ts2dt(x):
	t = []
	for a in x:
		t.append(ts2dt((a, None)))
	return t


LDAP_ATTRIBUTE_TYPES = {
	'supportedCapabilities' : list_str,
	'serverName' : list_str_one,
	'ldapServiceName': list_str_one,
	'dnsHostName' : list_str_one,
	'supportedSASLMechanisms' : list_str,
	'supportedLDAPPolicies' : list_str,
	'supportedLDAPVersion' : list_int,
	'supportedControl' : list_str,
	'rootDomainNamingContext' : list_str_one,
	'configurationNamingContext' : list_str_one,
	'schemaIDGUID' : x2guid,
	'lDAPDisplayName' : list_str_one, 
	'schemaNamingContext' : list_str_one,
	'defaultNamingContext' : list_str_one,
	'adminDescription' : list_str_one,
	'adminDisplayName' : list_str_one,
	'namingContexts' : list_str,
	'dsServiceName' : list_str_one,
	'subschemaSubentry' : list_str_one,
	'distinguishedName' : list_str_one,
	'objectCategory' : list_str_one,
	'userPrincipalName' : list_str_one,
	'sAMAccountType' : list_int_one,
	'sAMAccountName' : list_str_one,
	'logonCount' : list_int_one,
	'accountExpires' : int2dt,
	'objectSid' : x2sid,
	'primaryGroupID' : list_int_one,
	'pwdLastSet' : int2dt,
	'lastLogon' : int2dt,
	'lastLogoff' : int2dt,
	'lastLogonTimestamp' : int2dt,
	'badPasswordTime' : int2dt,
	'countryCode' : list_int_one,
	'codePage' : list_int_one,
	'badPwdCount' : list_int_one,
	'userAccountControl' : list_int_one,
	'objectGUID' : x2guid,
	'name' : list_str_one,
	'displayName' : list_str_one,
	'whenChanged' : ts2dt,
	'whenCreated' : ts2dt,
	'distinguishedName' : list_str_one,
	'givenName' : list_str_one,
	'cn' : list_str_one,
	'objectClass' : list_str,
	'dc' : list_str_one,
	'msDS-Behavior-Version' : list_int_one,
	'masteredBy' : list_str_one,
	'systemFlags' : list_int_one,
	'rIDManagerReference' : list_str_one,
	'auditingPolicy' : list_bytes_one,
	'uASCompat' : list_int_one,
	'serverState' : list_int_one,
	'nextRid' : list_int_one,
	'minPwdLength' : list_int_one,
	'minPwdAge' : int2timedelta,
	'lockoutThreshold' : list_int_one,
	'lockOutObservationWindow' : list_int_one,
	'lockoutDuration' : list_int_one,
	'forceLogoff' : int2timedelta,
	'creationTime' : int2dt,
	'maxPwdAge' : int2timedelta,
	'pwdHistoryLength' : list_int_one,
	'pwdProperties' : list_int_one,
	'uSNChanged' : list_int_one,
	'uSNCreated' : list_int_one,
	'instanceType' : list_int_one,
	'memberOf' : list_str,
	'description' : list_str_one,
	'servicePrincipalName' : list_str,
	'sn' : list_str_one,
	'initials' : list_str_one,
	#'nTSecurityDescriptor' : x2sd,
	'nTSecurityDescriptor' : list_bytes_one,
	'tokenGroups' : list_x2sid,
	'localPolicyFlags' : list_int_one,
	'msDS-SupportedEncryptionTypes' : list_int_one,
	'isCriticalSystemObject' : list_bool_one,
	'dNSHostName' : list_str_one,
	'operatingSystemVersion' : list_str_one,
	'operatingSystem' : list_str_one,
	'ou' : list_str_one,
	'showInAdvancedViewOnly' : list_bool_one,
	'gPLink' : list_str_one,
	'gPCFileSysPath' : list_str_one,
	'flags' : list_int_one,
	'versionNumber' : list_int_one,
	'gPCFunctionalityVersion' : list_int_one,
	'gPCMachineExtensionNames' : list_str,
	'gPCUserExtensionNames' : list_str,
	'groupType' : list_int_one,
	'member' : list_str,
	'adminCount' : list_int_one,
	'msDS-AllowedToDelegateTo' : list_str,
	'dSCorePropagationData' : ts2dt,
	'trustDirection' : list_int_one,
	'trustType' : list_int_one,
	'trustAttributes' : list_int_one,
	'flatName' : list_str_one,
	'trustPosixOffset' : list_int_one,
	'trustPartner' : list_str_one,
	'securityIdentifier' : list_bytes_one,
	'versionNumber' : list_int_one,
	'unicodePwd' : list_str_one,
	'ms-Mcs-AdmPwd' : list_str_one,
	'msDS-AllowedToActOnBehalfOfOtherIdentity' : list_bytes_one,
}

LDAP_ATTRIBUTE_TYPES_ENC = {
	'objectClass' : list_str_enc,
	'sn' : list_str_one_enc,
	'gidNumber' : list_int_one_enc,
	'unicodePwd' : list_str_one_utf16le_enc,
	'lockoutTime' : list_int_one_enc,
	'sAMAccountName' : list_str_one_enc,
	'userAccountControl' : list_int_one_enc,
	'displayName' : list_str_one_enc,
	'userPrincipalName' : list_str_one_enc,
	'servicePrincipalName' : list_str_enc,
	'msds-additionaldnshostname' : list_str_enc,
	'gPCMachineExtensionNames' : list_str_enc,
	'gPCUserExtensionNames' : list_str_enc,
	'versionNumber' : list_int_one_enc,
	'member' : list_str_enc,
	'msDS-AllowedToActOnBehalfOfOtherIdentity' : list_bytes_one_enc,
	'nTSecurityDescriptor' : list_bytes_one_enc,
}

def encode_attributes(x):
	"""converts a dict to attributelist"""
	res = []
	for k in x:
		if k not in LDAP_ATTRIBUTE_TYPES_ENC:
			raise Exception('Unknown conversion type for key "%s"' % k)
		
		res.append(Attribute({
			'type' : k.encode(),
			'attributes' : LDAP_ATTRIBUTE_TYPES_ENC[k](x[k])
		}))

	return res

def convert_attributes(x):
	t = {}
	for e in x:
		#print(e)
		k = e['type'].decode()
		#print('k: %s' % k)
		if k in LDAP_ATTRIBUTE_TYPES:
			t[k] = LDAP_ATTRIBUTE_TYPES[k](e['attributes'])
		else:
			logger.debug('Unknown type! %s data: %s' % (k, e['attributes']))
			t[k] = e['attributes']
	return t

def convert_result(x):
	#print(x)
	#import traceback
	#traceback.print_stack()
	return {
		'objectName' : x['objectName'].decode(),
		'attributes' : convert_attributes(x['attributes'])
	}


def encode_changes(x):
	res = []
	for k in x:
		if k not in LDAP_ATTRIBUTE_TYPES_ENC:
			raise Exception('Unknown conversion type for key "%s"' % k)
		
		for mod, value in x[k]:
			res.append(Change({
				'operation' : mod,
				'modification' : PartialAttribute({
					'type' : k.encode(),
					'attributes' : LDAP_ATTRIBUTE_TYPES_ENC[k](value)
				})
			}))
	return res