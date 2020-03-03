#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

# https://www.rfc-editor.org/rfc/rfc4178.txt

from asn1crypto.core import ObjectIdentifier, Sequence, SequenceOf, Enumerated, GeneralString, OctetString, BitString, Choice, Any, Boolean
import enum
import os
import io

TAG = 'explicit'

# class
UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2


class MechType(ObjectIdentifier):
	_map = {
		'1.3.6.1.4.1.311.2.2.10': 'NTLMSSP - Microsoft NTLM Security Support Provider',
		'1.2.840.48018.1.2.2'   : 'MS KRB5 - Microsoft Kerberos 5',
		'1.2.840.113554.1.2.2'  : 'KRB5 - Kerberos 5',
		'1.2.840.113554.1.2.2.3': 'KRB5 - Kerberos 5 - User to User',
		'1.3.6.1.4.1.311.2.2.30': 'NEGOEX - SPNEGO Extended Negotiation Security Mechanism',
}

class MechTypes(SequenceOf):
	_child_spec = MechType
	
class ContextFlags(BitString):
	_map = {
		0: 'delegFlag',
		1: 'mutualFlag',
		2: 'replayFlag',
		3: 'sequenceFlag',
		4: 'anonFlag',
		5: 'confFlag',
		6: 'integFlag',
}

class NegState(Enumerated):
	_map = {
		0: 'accept-completed',
		1: 'accept-incomplete',
		2: 'reject',
		3: 'request-mic',
}

class NegHints(Sequence):
	_fields = [
		('hintName', GeneralString, {'explicit': 0, 'optional': True}),
		('hintAddress', OctetString, {'explicit': 1, 'optional': True}),
]

# https://www.rfc-editor.org/rfc/rfc4178.txt 4.2.1
# EXTENDED IN: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/8e71cf53-e867-4b79-b5b5-38c92be3d472
class NegTokenInit2(Sequence):
	#explicit = (APPLICATION, 0)
	
	_fields = [
		('mechTypes', MechTypes, {'tag_type': TAG, 'tag': 0}),
		('reqFlags', ContextFlags, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('mechToken', OctetString, {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('negHints', NegHints, {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('mechListMIC', OctetString, {'tag_type': TAG, 'tag': 4, 'optional': True}),
]

# https://www.rfc-editor.org/rfc/rfc4178.txt 4.2.2

class NegTokenResp(Sequence):
	#explicit = (APPLICATION, 1)
	
	_fields = [
		('negState', NegState, {'tag_type': TAG, 'tag': 0, 'optional': True}),
		('supportedMech', MechType, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('responseToken', OctetString, {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('mechListMIC', OctetString, {'tag_type': TAG, 'tag': 3, 'optional': True}),
]


class NegotiationToken(Choice):
	_alternatives = [
		('negTokenInit', NegTokenInit2, {'explicit': (CONTEXT, 0) } ),
		('negTokenResp', NegTokenResp, {'explicit': (CONTEXT, 1) } ),
]


class GSS_SPNEGO(Sequence):
	class_ = 2
	tag    = 0

	_fields = [
		('NegotiationToken', NegotiationToken),
]

### I have 0 idea where this is tandardized :(
class GSSType(ObjectIdentifier):
	_map = { 
		#'': 'SNMPv2-SMI::enterprises.311.2.2.30',
		'1.3.6.1.5.5.2': 'SPNEGO',
	}

class GSSAPI(Sequence):
	class_ = 1
	tag    = 0

	_fields = [
		('type', GSSType, {'optional': False}),
		('value', Any, {'optional': False}),
	]

	_oid_pair = ('type', 'value')
	_oid_specs = {
		'SPNEGO': NegotiationToken,
	}

# https://tools.ietf.org/html/rfc2743#page-81
# You may think this is ASN1. But it truth, it's not.
# Below is a fucking disgrace of a protocol design.
class KRB5Token:
	def __init__(self, data = None, tok_id = b'\x01\x00'):
		self.tok_id = tok_id
		self.data = data
	
	
	@staticmethod
	def from_bytes(data):
		return KRB5Token.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		t = KRB5Token()
		buff.read(1)
		length = -1
		x = int.from_bytes(buff.read(1), 'big', signed = False)
		input(x)
		if x <= 127:
			length = x
		else:
			x &= ~0x80
			input(x)
			length = int.from_bytes(buff.read(x), 'big', signed = False)
			input('length: %s' % length)
		oid_asn1 = buff.read(11)
		t.tok_id = int.from_bytes(buff.read(2), 'big', signed = False)
		t.data = buff.read(length-13)
		input(t.tok_id )
		return t
		
	def length_encode(self, x):
		if x <= 127:
			return x.to_bytes(1, 'big', signed = False)
		else:
			lb = x.to_bytes((x.bit_length() + 7) // 8, 'big')
			t = (0x80 | len(lb)).to_bytes(1, 'big', signed = False)
			return t+lb
		
	def to_bytes(self):
		t = b'\x60' #
		t += self.length_encode(11 + 2 + len(self.data))
		t += bytes.fromhex('06092a864886f712010202') #OID length + OID for kerberos 
		t += self.tok_id 
		t += self.data
		return t