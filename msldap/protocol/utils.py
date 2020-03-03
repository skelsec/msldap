from ldap_filter import Filter as LF
from msldap.protocol.messages import Filter, Filters

def query_syntax_converter_inner(ftr):
		if ftr.type == 'filter':
			if ftr.comp == '=':
				key = 'equalityMatch'
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

    

def calcualte_length(data):
	"""
	LDAP protocol doesnt send the total length of the message in the header,
	it only sends raw ASN1 encoded data structures, which has the length encoded.
	This function "decodes" the length os the asn1 structure, and returns it as int.
	"""
	if data[1] <= 127:
		return data[1] + 2
	else:
		bcount = data[1] - 128
		if (bcount +2 ) > len(data):
			raise Exception('LDAP data too larage! Length byte count: %s' % bcount)
		return int.from_bytes(data[2:2+bcount], byteorder = 'big', signed = False) + bcount + 2



