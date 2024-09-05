from .ldap_filter import Filter as LF
from .ldap_filter.filter import LDAPBase
from asn1crypto.core import ObjectIdentifier
from msldap.protocol.messages import Filter, Filters, \
	AttributeDescription, SubstringFilter, MatchingRuleAssertion, \
	Substrings, Substring


def equality(attr, value):
	if attr[-1] == ':':
		name, oid_raw = attr[:-1].split(':')
		return Filter({
				'extensibleMatch' : MatchingRuleAssertion({
						'matchingRule' : oid_raw.encode(),
						'type' : name.encode(),
						'matchValue' : rfc4515_encode(value),
						'dnAttributes' : False
					})
				})

	elif value == '*':
		return Filter({
				'present' : AttributeDescription(attr.encode())
			})

	elif value.startswith('*') and value.endswith('*'):
		return Filter({
				'substrings' : SubstringFilter({
					'type' : attr.encode(),
					'substrings' : Substrings([
							Substring({
								'any' : rfc4515_encode(value[1:-1])
							})
						])
				})
			})

	elif value.startswith('*') is True:
		return Filter({
				'substrings' : SubstringFilter({
					'type' : attr.encode(),
					'substrings' : Substrings([
							Substring({
								'final' : rfc4515_encode(value[1:])
							})
						])
				})
			})
	
	elif value.endswith('*') is True:
		return Filter({
				'substrings' : SubstringFilter({
					'type' : attr.encode(),
					'substrings' : Substrings([
							Substring({
								'initial' : rfc4515_encode(value[:-1])
							})
						])
				})
			})
				
	else:
		return Filter({
				'equalityMatch' : {
					'attributeDesc' : attr.encode(),
					'assertionValue' : rfc4515_encode(value)
				}
			})
	

def query_syntax_converter_inner(ftr):
		if ftr.type == 'filter':
			if ftr.comp == '=':
				return equality(ftr.attr, ftr.val)
			elif ftr.comp == '<=':
				key = 'lessOrEqual'
			elif ftr.comp == '>=':
				key = 'greaterOrEqual'
			elif ftr.comp == '~=':
				key = 'approxMatch'
				
			return Filter({
				key : {
					'attributeDesc' : ftr.attr.encode(),
					'assertionValue' : rfc4515_encode(ftr.val)
				}
			})
		
		
		elif ftr.type == 'group':
			if ftr.comp == '&' or ftr.comp == '|':
				if ftr.comp == '&':
					key = 'and'
				elif ftr.comp == '|':
					key = 'or'
				
				#x = [query_syntax_converter_inner(f) for f in ftr.filters]
				return Filter({
					key : Filters([query_syntax_converter_inner(f) for f in ftr.filters])
				})
			elif ftr.comp == '!':
				return Filter({
					#'not' : Filter(ftr.filters[0])
					'not' : query_syntax_converter_inner(ftr.filters[0])
				})

def query_syntax_converter(ldap_query_string):
	"""
	Converts and LDAP query string into a ASN1 Filter object.
	warning: the parser has a name collision with the asn1 strucutre!
	"""
	flt = LF.parse(ldap_query_string)
	return query_syntax_converter_inner(flt)


def escape_filter_chars(text):
    return LDAPBase.escape(text)

def rfc4515_encode(value):
	i = 0
	byte_str = b''
	while i < len(value):
		if (value[i] == '\\') and i < len(value) - 2:
			try:
				byte_str += int(value[i + 1: i + 3], 16).to_bytes()
				i += 2
			except ValueError:  # not an ldap escaped value, sends as is
				byte_str += b'\\'
		else:
				byte_str += value[i].encode()
		i += 1
	return byte_str