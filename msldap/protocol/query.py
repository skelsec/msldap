from ldap_filter import Filter as LF
from asn1crypto.core import ObjectIdentifier
from msldap.protocol.messages import Filter, Filters, \
	AttributeDescription, SubstringFilter, MatchingRuleAssertion, \
	SubstringFilter




#Filter._alternatives = [
#		('and', Filters, {'implicit': (CONTEXT , 0) }  ),
#		('or', Filters, {'implicit': (CONTEXT , 1) }  ),
#		('not', Filter, {'implicit': (CONTEXT , 2) }  ),
#		('equalityMatch', AttributeValueAssertion, {'implicit': (CONTEXT , 3) }  ),
#		('substrings', SubstringFilter, {'implicit': (CONTEXT , 4) }  ),
#		('greaterOrEqual', AttributeValueAssertion, {'implicit': (CONTEXT , 5) }  ),
#		('lessOrEqual', AttributeValueAssertion, {'implicit': (CONTEXT , 6) }  ),
#		('present', AttributeDescription, {'implicit': (CONTEXT , 7) }  ),
#		('approxMatch', AttributeValueAssertion, {'implicit': (CONTEXT , 8) }  ),
#		('extensibleMatch', MatchingRuleAssertion, {'implicit': (CONTEXT , 9) }  ),
#
#	]

def equality(attr, value):
	print(attr)
	if attr[-1] == ':':
		#possible OID
		name, oid_raw = attr[:-1].split(':')
		print(oid_raw)
		return Filter({
				'extensibleMatch' : MatchingRuleAssertion({
						'matchingRule' : oid_raw.encode(),
						'type' : name.encode(),
						'matchValue' : value.encode(),
						'dnAttributes' : False
					})
				})

	elif value == '*':
		return Filter({
				'present' : AttributeDescription(attr.encode())
			})

	#elif value.startswith('*'):
	#	
	#	return Filter({
	#			'equalityMatch' : SubstringFilter({
	#				'attributeDesc' : attr.encode(),
	#				'assertionValue' : value.encode()
	#			}
	#		})
				
	else:
		return Filter({
				'equalityMatch' : {
					'attributeDesc' : attr.encode(),
					'assertionValue' : value.encode()
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
					'assertionValue' : ftr.val.encode()
				}
			})
		
		
		elif ftr.type == 'group':
			if ftr.comp == '&' or ftr.comp == '|':
				if ftr.comp == '&':
					key = 'and'
				elif ftr.comp == '|':
					key = 'or'
				
				x = [query_syntax_converter_inner(f) for f in ftr.filters]
				print(x)
				Filters(x)
				return Filter({
					key : Filters([query_syntax_converter_inner(f) for f in ftr.filters])
				})
			elif ftr.comp == '!':
				return Filter({
					'not' : Filter(ftr.filters[0])
				})

def query_syntax_converter(ldap_query_string):
	"""
	Converts and LDAP query string into a ASN1 Filter object.
	warning: the parser has a name collision with the asn1 strucutre!
	"""
	flt = LF.parse(ldap_query_string)
	return query_syntax_converter_inner(flt)