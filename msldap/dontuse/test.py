
import sys

from ldap3.operation.search import parse_filter, compile_filter
from ldap3.protocol.schemas.ad2012R2 import ad_2012_r2_schema, ad_2012_r2_dsa_info
from ldap3.protocol.rfc4512 import SchemaInfo
from pyasn1.codec.der import decoder, encoder

from msldap.protocol.query import query_syntax_converter
from msldap.protocol.messages import LDAPMessage, Filter

# https://ldap3.readthedocs.io/bind.html
if __name__ == '__main__':

	qry = r'(&(servicePrincipalName=*)(!(sAMAccountName=*$)))'

	schema = SchemaInfo.from_json(ad_2012_r2_schema)
	auto_escape = True
	auto_encode = True
	validator = None
	check_names = False
	
	
	res = parse_filter(qry, schema, auto_escape, auto_encode, validator, check_names)
	print(repr(res))
	res = compile_filter(res.elements[0])
	print(repr(res))
	print(encoder.encode(res).hex())

	msg = Filter.load(encoder.encode(res))
	print(msg.native)

	sys.exit()
	
	qry = r'(sAMAccountName=*)' #'(userAccountControl:1.2.840.113556.1.4.803:=4194304)' #'(sAMAccountName=*)'
	#qry = r'(sAMAccountType=805306368)'
	#a = query_syntax_converter(qry)
	#print(a.native)
	#input('press bacon!')
	schema = SchemaInfo.from_json(ad_2012_r2_schema)
	auto_escape = True
	auto_encode = True
	validator = None
	check_names = False
#
#
	res = parse_filter(qry, schema, auto_escape, auto_encode, validator, check_names)
	print(repr(res))
	res = compile_filter(res.elements[0])
#
	print(repr(res))
	print(encoder.encode(res).hex())
	#res = encoder.encode(res)
	#x = Filter.load(res)
	#pprint(x.native)

	
	flt = query_syntax_converter(qry)
	input(flt.native)

	#res = await client.search_test_2()
	#pprint.pprint(res)
	#search = bytes.fromhex('30840000007702012663840000006e043c434e3d3430392c434e3d446973706c6179537065636966696572732c434e3d436f6e66696775726174696f6e2c44433d746573742c44433d636f72700a01000a010002010002020258010100870b6f626a656374436c61737330840000000d040b6f626a656374436c617373')
	#msg = LDAPMessage.load(search)
