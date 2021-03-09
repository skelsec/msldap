#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

# https://tools.ietf.org/html/rfc4511
# https://msdn.microsoft.com/en-us/library/cc223501.aspx


from asn1crypto import core
import enum
import os

TAG = 'explicit'

# class
UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2

#https://msdn.microsoft.com/en-us/library/cc223359.aspx
class MSLDAPCapabilities(core.ObjectIdentifier):
	_map = {
		'1.2.840.113556.1.4.800' : 'LDAP_CAP_ACTIVE_DIRECTORY_OID',
		'1.2.840.113556.1.4.1791': 'LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID',
		'1.2.840.113556.1.4.1670': 'LDAP_CAP_ACTIVE_DIRECTORY_V51_OID',
		'1.2.840.113556.1.4.1880': 'LDAP_CAP_ACTIVE_DIRECTORY_ADAM_DIGEST_OID',
		'1.2.840.113556.1.4.1851': 'LDAP_CAP_ACTIVE_DIRECTORY_ADAM_OID',
		'1.2.840.113556.1.4.1920': 'LDAP_CAP_ACTIVE_DIRECTORY_PARTIAL_SECRETS_OID',
		'1.2.840.113556.1.4.1935': 'LDAP_CAP_ACTIVE_DIRECTORY_V60_OID',
		'1.2.840.113556.1.4.2080': 'LDAP_CAP_ACTIVE_DIRECTORY_V61_R2_OID',
		'1.2.840.113556.1.4.2237': 'LDAP_CAP_ACTIVE_DIRECTORY_W8_OID',
	}

class scope(core.Enumerated):
	_map = {
		0 : 'baseObject',
		1 : 'singleLevel',
		2 : 'wholeSubtree',
	}

class derefAliases(core.Enumerated):
	_map = {
		0 : 'neverDerefAliases',
		1 : 'derefInSearching',
		2 : 'derefFindingBaseObj',
		3 : 'derefAlways',
	}

class resultCode(core.Enumerated):
	_map = {
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

class ChangeOperation(core.Enumerated):
	_map = {
		0 : 'add',
		1 : 'delete',
		2 : 'replace',
	}	

class LDAPString(core.OctetString):
	pass
	
class LDAPDN(core.OctetString):
	pass
	
class LDAPOID(core.OctetString):
	pass
	
class URI(LDAPString):
	pass
	
class Referral(core.SequenceOf):
	_child_spec = URI

# https://www.ietf.org/rfc/rfc2696.txt
class SearchControlValue(core.Sequence):
	_fields = [
		('size' , core.Integer),
		('cookie' , core.OctetString)
	]

class Control(core.Sequence):
	_fields = [
		('controlType', LDAPOID),
		('criticality', core.Boolean, {'default' : False }),
		('controlValue', core.OctetString, {'optional': True })	,
	]
	
class Controls(core.SequenceOf):
	_child_spec = Control
	
class SaslCredentials(core.Sequence):
	_fields = [
		('mechanism', core.OctetString),
		('credentials', core.OctetString, {'optional': True}),	
	]
	
class SicilyPackageDiscovery(core.OctetString):
	pass

class SicilyNegotiate(core.OctetString):
	pass

class SicilyResponse(core.OctetString):
	pass
	
class AuthenticationChoice(core.Choice):
	_alternatives = [
		('simple', core.OctetString, {'implicit': (CONTEXT, 0)}),
		('sasl', SaslCredentials, {'implicit': (CONTEXT, 3)}),
		('sicily_disco', SicilyPackageDiscovery, {'implicit': (CONTEXT, 9)}), # FUCK
		('sicily_nego', SicilyNegotiate, {'implicit': (CONTEXT, 10)}), #YOU
		('sicily_resp', SicilyResponse, {'implicit': (CONTEXT, 11)}), #MICROSOFT
	]

class BindRequest(core.Sequence):
	_fields = [
		('version', core.Integer),
		('name', core.OctetString),
		('authentication', AuthenticationChoice),	
	]
	
class BindResponse(core.Sequence):
	_fields = [
		('resultCode', resultCode),
		('matchedDN', LDAPDN),
		('diagnosticMessage', LDAPString),
		('referral', Referral, {'optional': True}),
		('serverSaslCreds', core.OctetString, {'implicit': (CONTEXT, 7), 'optional': True}),
	]

class AttributeDescription(LDAPString):
	pass

class AttributeValue(core.OctetString):
	pass


class MatchingRuleId(LDAPString):
	pass

class AssertionValue(core.OctetString):
	pass

class AttributeValueAssertion(core.Sequence):
	_fields = [
		('attributeDesc', AttributeDescription),
		('assertionValue', AssertionValue),
	]

class Substring(core.Choice):
	_alternatives = [
		('initial', AssertionValue, {'implicit': (CONTEXT , 0) }  ),
		('any', AssertionValue, {'implicit': (CONTEXT , 1) }  ),
		('final', AssertionValue, {'implicit': (CONTEXT , 2) }  ),
	]
	

class Substrings(core.SequenceOf):
	_child_spec = Substring

class SubstringFilter(core.Sequence):
	_fields = [
		('type', AttributeDescription),
		('substrings', Substrings),
	]

class MatchingRuleAssertion(core.Sequence):
	_fields = [
		('matchingRule', MatchingRuleId, {'implicit': (CONTEXT, 1), 'optional' : True}  ),
		('type', AttributeDescription, {'implicit': (CONTEXT, 2), 'optional' : True}  ),
		('matchValue', AssertionValue, {'implicit': (CONTEXT, 3)}  ),
		('dnAttributes', core.Boolean, {'implicit': (CONTEXT, 4), 'default' : False}  ),
	]

# keep this Filter definition here! It is needed because filter class contains itself!
class Filter(core.Choice):
	pass

class Filters(core.SequenceOf):
	_child_spec = Filter

Filter._alternatives = [
		('and', Filters, {'implicit': (CONTEXT , 0) }  ),
		('or', Filters, {'implicit': (CONTEXT , 1) }  ),
		('not', Filter, {'explicit': (CONTEXT , 2) }  ), # https://tools.ietf.org/html/rfc4511#section-4.5.1.8
		('equalityMatch', AttributeValueAssertion, {'implicit': (CONTEXT , 3) }  ),
		('substrings', SubstringFilter, {'implicit': (CONTEXT , 4) }  ),
		('greaterOrEqual', AttributeValueAssertion, {'implicit': (CONTEXT , 5) }  ),
		('lessOrEqual', AttributeValueAssertion, {'implicit': (CONTEXT , 6) }  ),
		('present', AttributeDescription, {'implicit': (CONTEXT , 7) }  ),
		('approxMatch', AttributeValueAssertion, {'implicit': (CONTEXT , 8) }  ),
		('extensibleMatch', MatchingRuleAssertion, {'implicit': (CONTEXT , 9) }  ),

	]

class AttributeSelection(core.SequenceOf):
	_child_spec = LDAPString

class SearchRequest(core.Sequence):
	_fields = [
		('baseObject', LDAPDN),
		('scope', scope),
		('derefAliases', derefAliases),
		('sizeLimit', core.Integer),
		('timeLimit', core.Integer),
		('typesOnly', core.Boolean),
		('filter', Filter),
		('attributes', AttributeSelection),
	]

class AttributeValueSet(core.SetOf):
	_child_spec = AttributeValue


class PartialAttribute(core.Sequence):
	_fields = [
		('type', AttributeDescription),
		('attributes', AttributeValueSet),
	]

class PartialAttributeList(core.SequenceOf):
	_child_spec = PartialAttribute

class SearchResultEntry(core.Sequence):
	_fields = [
		('objectName', LDAPDN),
		('attributes', PartialAttributeList),
	]

class SearchResultReference(core.SequenceOf):
	_child_spec = URI

class UnbindRequest(core.Null):
	pass

class LDAPResult(core.Sequence):
	_fields = [
		('resultCode', resultCode ),
		('matchedDN', LDAPDN),
		('diagnosticMessage', LDAPString),
		('referral', Referral,  {'implicit': (CONTEXT, 3), 'optional': True}),
	]

class SearchResultDone(LDAPResult):
	pass

class Change(core.Sequence):
	_fields = [
		('operation', ChangeOperation),
		('modification', PartialAttribute),
	]

class Changes(core.SequenceOf):
	_child_spec = Change

class ModifyRequest(core.Sequence):
	_fields = [
		('object', LDAPDN),
		('changes', Changes),
	]

class ModifyResponse(LDAPResult):
	pass

class Attribute(PartialAttribute):
	pass

class AttributeList(core.SequenceOf):
	_child_spec = Attribute

class AddRequest(core.Sequence):
	_fields = [
		('entry', LDAPDN),
		('attributes', AttributeList),
	]

class AddResponse(LDAPResult):
	pass

class DelRequest(LDAPDN):
	pass

class DelResponse(LDAPResult):
	pass

class RelativeLDAPDN(LDAPString):
	pass

class ModifyDNRequest(core.Sequence):
	_fields = [
		('entry', LDAPDN),
		('newrdn', RelativeLDAPDN),
		('deleteoldrdn', core.Boolean),
		('deleteoldrdn', LDAPDN),
		('newSuperior', LDAPDN, {'optional': True}),
		
	]

class ModifyDNResponse(LDAPResult):
	pass

class CompareRequest(core.Sequence):
	_fields = [
		('entry', LDAPDN),
		('ava', AttributeValueAssertion),		
	]

class CompareResponse(LDAPResult):
	pass

class ExtendedRequest(core.Sequence):
	_fields = [
		('requestName', LDAPOID, {'implicit': (CONTEXT , 0) }),
		('requestValue', core.OctetString, {'implicit': (CONTEXT , 1), 'optional' : True}),		
	]

class ExtendedResponse(core.Sequence):
	_fields = [
		('resultCode', resultCode ),
		('matchedDN', LDAPDN),
		('diagnosticMessage', LDAPString),
		('referral', Referral,  {'implicit': (CONTEXT, 3), 'optional': True}),
		('responseName', LDAPOID, {'implicit': (CONTEXT , 10) , 'optional' : True}),
		('responseValue', core.OctetString, {'implicit': (CONTEXT , 11) , 'optional' : True}),
	]

class IntermediateResponse(core.Sequence):
	_fields = [
		('responseName', LDAPOID, {'implicit': (CONTEXT , 0) , 'optional' : True}),
		('responseValue', core.OctetString, {'implicit': (CONTEXT , 1) , 'optional' : True}),
	]

class protocolOp(core.Choice):
	_alternatives = [
		('bindRequest', BindRequest, {'implicit': (APPLICATION , 0) }  ),
		('bindResponse', BindResponse, {'implicit': (APPLICATION , 1) }  ),
		('unbindRequest', UnbindRequest, {'implicit': (APPLICATION,2) }  ),
		('searchRequest', SearchRequest, {'implicit': (APPLICATION,3) }  ),
		('searchResEntry', SearchResultEntry, {'implicit': (APPLICATION,4) }  ),
		('searchResDone', SearchResultDone, {'implicit': (APPLICATION,5) }  ),
		('modifyRequest', ModifyRequest, {'implicit': (APPLICATION,6) }  ),
		('modifyResponse', ModifyResponse, {'implicit': (APPLICATION,7) }  ),
		('addRequest', AddRequest, {'implicit': (APPLICATION,8) }  ),
		('addResponse', AddResponse, {'implicit': (APPLICATION,9) }  ),
		('delRequest', DelRequest, {'implicit': (APPLICATION,10) }  ),
		('delResponse', DelResponse, {'implicit': (APPLICATION,11) }  ),
		('modDNRequest', ModifyDNRequest, {'implicit': (APPLICATION,12) }  ),
		('modDNResponse', ModifyDNResponse, {'implicit': (APPLICATION,13) }  ),
		('compareRequest', CompareRequest, {'implicit': (APPLICATION,14) }  ),
		('compareResponse', CompareResponse, {'implicit': (APPLICATION,15) }  ),
		('abandonRequest', core.Integer, {'implicit': (APPLICATION,16) }  ), #integer is the messageid to abandon
		('searchResRef', SearchResultReference, {'implicit': (APPLICATION,19) }  ),
		('extendedReq', ExtendedRequest, {'implicit': (APPLICATION,23) }  ),
		('extendedResp', ExtendedResponse, {'implicit': (APPLICATION,24) }  ),
		('intermResponse', IntermediateResponse, {'implicit': (APPLICATION,25) }  ),
		
	]
	
class LDAPMessage(core.Sequence):
	_fields = [
		('messageID', core.Integer),
		('protocolOp', protocolOp),
		('controls', Controls, {'implicit': (CONTEXT, 0), 'optional': True}),	
	]
	
