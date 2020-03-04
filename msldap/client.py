import asyncio

from msldap import logger
from msldap.protocol.messages import LDAPMessage, BindRequest, \
	protocolOp, AuthenticationChoice, SaslCredentials, \
	SearchRequest, AttributeDescription, Filter, Filters, \
	Controls, Control, SearchControlValue

from msldap.protocol.utils import calcualte_length
from msldap.commons.authbuilder import AuthenticatorBuilder
from msldap.network.selector import MSLDAPNetworkSelector
import pprint

class MSLDAPClientConnection:
	def __init__(self, target, creds):
		self.target = target
		self.creds = creds
		self.auth = AuthenticatorBuilder(self.creds, self.target).build()
		self.connected = False
		self.bind_ok = False
		self.__sign_messages = False
		self.__encrypt_messages = False
		self.network = None

		self.handle_incoming_task = None

		self.message_id = 0
		self.message_table = {}
		self.message_table_notify = {}

	async def __handle_incoming(self):
		try:
			while True:
				message_data, err = await self.network.in_queue.get()
				if err is not None:
					logger.debug('Client terminating bc __handle_incoming!')
					raise err
				
				################################
				#                              #
				#  ADD CHANNEL BINDING  HERE!  #
				################################

				if self.bind_ok is True:
					if self.__encrypt_messages is True:
						#print('Encrypted %s' % message_data)
						#removing size
						message_data = message_data[4:]
						try:
							message_data = await self.auth.decrypt(message_data, 0)
							#print('Decrypted %s' % message_data.hex())
						except:
							import traceback
							traceback.print_exc()
						
					elif self.__sign_messages is True:
						#print('Signed %s' % message_data)
						message_data = message_data[4:]
						try:
							message_data = await self.auth.unsign(message_data)
						#	print('Unsinged %s' % message_data)
						except:
							import traceback
							traceback.print_exc()
				
				msg_len = calcualte_length(message_data)
				msg_total_len = len(message_data)
				messages = []
				if msg_len == msg_total_len:
					message = LDAPMessage.load(message_data)
					messages.append(message.native)
				else:
					#print('multi-message!')
					while len(message_data) > 0:
						msg_len = calcualte_length(message_data)
						message = LDAPMessage.load(message_data[:msg_len])
						messages.append(message.native)
						
						message_data = message_data[msg_len:]

				#print(messages)
				message_id = messages[0]['messageID']
				if message_id not in self.message_table:
					self.message_table[message_id] = []
				self.message_table[message_id].extend(messages)
				if message_id not in self.message_table_notify:
					self.message_table_notify[message_id] = asyncio.Event()
				self.message_table_notify[message_id].set()
		except Exception as e:
			import traceback
			traceback.print_exc()
			for msgid in self.message_table_notify:
				self.message_table[msgid] = [e]
				self.message_table_notify[msgid].set()


	async def send_message(self, message):
		curr_msg_id = self.message_id
		self.message_id += 1

		message['messageID'] = curr_msg_id
		message_data = LDAPMessage(message).dump()

		if self.bind_ok is True:
			if self.__encrypt_messages is True:
				message_data, signature = await self.auth.encrypt(message_data, 0)
				message_data = signature + message_data
				message_data = len(message_data).to_bytes(4, byteorder = 'big', signed = False) + message_data
			elif self.__sign_messages is True:
				signature = await self.auth.sign(message_data, 0)
				message_data = signature + message_data
				message_data = len(message_data).to_bytes(4, byteorder = 'big', signed = False) + message_data
		
		self.message_table_notify[curr_msg_id] = asyncio.Event()
		await self.network.out_queue.put(message_data)

		return curr_msg_id

	async def recv_message(self, message_id):
		if message_id not in self.message_table_notify:
			logger.debug('Requested message id %s which is not in the message notify table!' % message_id)
			return None
		#print('Waiting for %s' % message_id)
		await self.message_table_notify[message_id].wait()
		#print(self.message_table)
		messages = self.message_table[message_id]

		#print('%s arrived!' % message_id)

		self.message_table[message_id] = []
		self.message_table_notify[message_id].clear()

		return messages

	async def connect(self):
		logger.debug('Connecting!')
		self.network = MSLDAPNetworkSelector.select(self.target)
		res, err = await self.network.run()
		if res is False:
			raise err

		self.handle_incoming_task = asyncio.create_task(self.__handle_incoming())
		logger.debug('Connection succsessful!')

	def __bind_success(self):
		"""
		Internal function invoked after bind finished. 
		Instructs the network layer that upcoming messages might be wrapped
		"""
		logger.debug('BIND Success!')
		self.bind_ok = True
		self.__sign_messages = self.auth.signing_needed()
		self.__encrypt_messages = self.auth.encryption_needed()
		if self.__encrypt_messages or self.__sign_messages:
			self.network.is_plain_msg = False

	async def bind(self):
		
		if self.creds.auth_method == LDAPAuthProtocol.NTLM:
			data, _ = await self.auth.authenticate(None)
			
			auth = {
				'sicily_disco' : b''
			}

			bindreq = {
				'version' : 3,
				'name' : 'NTLM'.encode(),
				'authentication': AuthenticationChoice(auth), 
			}

			br = { 'bindRequest' : BindRequest( bindreq	)}
			msg = { 'protocolOp' : protocolOp(br)}
			
			msg_id = await self.send_message(msg)
			res = await self.recv_message(msg_id)
			res = res[0]
			if res['protocolOp']['resultCode'] != 'success':
				raise Exception(
					'BIND failed! Result code: "%s" Reason: "%s"' % (
						res['protocolOp']['resultCode'], 
						res['protocolOp']['diagnosticMessage']
					))
			
			auth = {
				'sicily_nego' : data
			}

			bindreq = {
				'version' : 3,
				'name' : 'NTLM'.encode(),
				'authentication': AuthenticationChoice(auth), 
			}

			br = { 'bindRequest' : BindRequest( bindreq	)}
			msg = { 'protocolOp' : protocolOp(br)}
			
			msg_id = await self.send_message(msg)
			res = await self.recv_message(msg_id)
			res = res[0]
			if res['protocolOp']['resultCode'] != 'success':
				raise Exception(
					'BIND failed! Result code: "%s" Reason: "%s"' % (
						res['protocolOp']['resultCode'], 
						res['protocolOp']['diagnosticMessage']
					))

			data, _ = await self.auth.authenticate(res['protocolOp']['matchedDN'])

			auth = {
				'sicily_resp' : data
			}

			bindreq = {
				'version' : 3,
				'name' : 'NTLM'.encode(),
				'authentication': AuthenticationChoice(auth), 
			}

			br = { 'bindRequest' : BindRequest( bindreq	)}
			msg = { 'protocolOp' : protocolOp(br)}
			
			msg_id = await self.send_message(msg)
			res = await self.recv_message(msg_id)
			res = res[0]
			if res['protocolOp']['resultCode'] != 'success':
				raise Exception(
					'BIND failed! Result code: "%s" Reason: "%s"' % (
						res['protocolOp']['resultCode'], 
						res['protocolOp']['diagnosticMessage']
					))
			

			self.__bind_success()
			return True

		elif self.creds.auth_method == LDAPAuthProtocol.GSSAPI:
			challenge = None
			while True:
				data, _ = await self.auth.authenticate(challenge)
				
				sasl = {
					'mechanism' : 'GSS-SPNEGO'.encode(),
					'credentials' : data,
				}
				auth = {
					'sasl' : SaslCredentials(sasl)
				}

				bindreq = {
					'version' : 3,
					'name': ''.encode(),
					'authentication': AuthenticationChoice(auth), 
				}

				br = { 'bindRequest' : BindRequest( bindreq	)}
				msg = { 'protocolOp' : protocolOp(br)}
				
				msg_id = await self.send_message(msg)
				res = await self.recv_message(msg_id)
				res = res[0]
				if res['protocolOp']['resultCode'] == 'success':
					self.__bind_success()
					return True

				elif res['protocolOp']['resultCode'] == 'saslBindInProgress':
					challenge = res['protocolOp']['serverSaslCreds']
					continue

				else:
					raise Exception(
						'BIND failed! Result code: "%s" Reason: "%s"' % (
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						))
				
				#print(res)
	
	async def search(self, base, filter, attributes, scope = 2, sizeLimit = 1000, typesOnly = False, derefAliases = 0, timeLimit = None, controls = None, return_done = False):
		"""
		This function is a generator!!!!! Dont just call it but use it with "async for"
		"""
		if timeLimit is None:
			timeLimit = 600 #not sure
		
		searchreq = {
			'baseObject' : base,
			'scope': scope,
			'derefAliases': derefAliases, 
			'sizeLimit': sizeLimit,
			'timeLimit': timeLimit,
			'typesOnly': typesOnly,
			'filter': filter,
			'attributes': attributes,
		}

		br = { 'searchRequest' : SearchRequest( searchreq	)}
		msg = { 'protocolOp' : protocolOp(br)}
		if controls is not None:
			msg['controls'] = controls

		msg_id = await self.send_message(msg)
		
		while True:
			results = await self.recv_message(msg_id)
			for message in results:
				if 'resultCode' in message['protocolOp']:
					#print(message)
					#print('BREAKING!')
					if return_done is True:
						yield message
					break
				yield message
			else:
				continue
			
			break

	async def pagedsearch(self, base, filter, attributes, scope = 2, sizeLimit = 1000, typesOnly = False, derefAliases = 0, timeLimit = None, controls = None):
		cookie = b''
		while True:
			
			ctrl_list_temp = [
				Control({
					'controlType' : b'1.2.840.113556.1.4.319',
					'controlValue': SearchControlValue({
						'size' : sizeLimit,
						'cookie': cookie
					}).dump()
				})
			]
			if controls is not None:
				ctrl_list_temp.extend(controls)
			
			ctrs = Controls(
				ctrl_list_temp
			)


			async for res in self.search(
				base, 
				filter, 
				attributes, 
				scope = scope, 
				sizeLimit=sizeLimit, 
				typesOnly=typesOnly, 
				derefAliases=derefAliases, 
				timeLimit=timeLimit, 
				controls = ctrs,
				return_done = True
				):
					if 'resultCode' in res['protocolOp']:
						for control in res['controls']:
							if control['controlType'] == b'1.2.840.113556.1.4.319':
								try:
									cookie = SearchControlValue.load(control['controlValue']).native['cookie']
								except:
									print(res)
									import traceback
									traceback.print_exc()
									raise e
								break
						else:
							raise Exception('SearchControl missing from server response!')
					else:
						yield res

			if cookie == b'':
				break

		

	async def search_test(self):
		filt = { 'present' : 'objectClass'.encode() }
		searchreq = {
			'baseObject' : 'CN=409,CN=DisplaySpecifiers,CN=Configuration,DC=test,DC=corp'.encode(),
			'scope': 0,
			'derefAliases': 0, 
			'sizeLimit': 1,
			'timeLimit': self.target.timeout - 1,
			'typesOnly': False,
			'filter': Filter(filt),
			'attributes': ['objectClass'.encode()],
		}

		br = { 'searchRequest' : SearchRequest( searchreq	)}
		msg = { 'protocolOp' : protocolOp(br)}

		msg_id = await self.send_message(msg)
		res = await self.recv_message(msg_id)
		print(res)

	async def search_test_2(self):
		attributes = [
			b'subschemaSubentry',
    		b'dsServiceName',
    		b'namingContexts',
    		b'defaultNamingContext',
    		b'schemaNamingContext',
    		b'configurationNamingContext',
    		b'rootDomainNamingContext',
    		b'supportedControl',
    		b'supportedLDAPVersion',
    		b'supportedLDAPPolicies',
    		b'supportedSASLMechanisms',
    		b'dnsHostName',
    		b'ldapServiceName',
    		b'serverName',
    		b'supportedCapabilities'
		]

		filt = { 'present' : 'objectClass'.encode() }
		searchreq = {
			'baseObject' : b'',
			'scope': 0,
			'derefAliases': 0, 
			'sizeLimit': 1,
			'timeLimit': self.target.timeout - 1,
			'typesOnly': False,
			'filter': Filter(filt),
			'attributes': attributes,
		}

		br = { 'searchRequest' : SearchRequest( searchreq	)}
		msg = { 'protocolOp' : protocolOp(br)}

		msg_id = await self.send_message(msg)
		res = await self.recv_message(msg_id)
		#if res['protocolOp']['resultCode'] == 'success':
		#	logger.debug('SEARCH Success!')
		return res

async def amain():
	base = 'DC=TEST,DC=CORP'

	ip = '10.10.10.2'
	domain = 'TEST'
	username = 'victim'
	password = 'Passw0rd!1'
	auth_method = LDAPAuthProtocol.NTLM
	##auth_method = LDAPAuthProtocol.GSSAPI

	cred = MSLDAPCredential(domain, username, password , auth_method)
	target = MSLDAPTarget(ip)

	client = MSLDAPClientConnection(target, cred)
	await client.connect()
	await client.bind()
	
	#res = await client.search_test_2()
	#pprint.pprint(res)
	#search = bytes.fromhex('30840000007702012663840000006e043c434e3d3430392c434e3d446973706c6179537065636966696572732c434e3d436f6e66696775726174696f6e2c44433d746573742c44433d636f72700a01000a010002010002020258010100870b6f626a656374436c61737330840000000d040b6f626a656374436c617373')
	#msg = LDAPMessage.load(search)

	from ldap3.operation.search import parse_filter, compile_filter
	from ldap3.protocol.schemas.ad2012R2 import ad_2012_r2_schema, ad_2012_r2_dsa_info
	from ldap3.protocol.rfc4512 import SchemaInfo
	from pyasn1.codec.der import decoder, encoder
	
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
	i = 0
	async for res in client.pagedsearch(base.encode(), flt, ['*'.encode()], derefAliases=3, typesOnly=False):
		i += 1
		if i % 1000 == 0:
			print(i)
		#pprint.pprint(res)



if __name__ == '__main__':
	from msldap import logger
	from msldap.commons.credential import MSLDAPCredential, LDAPAuthProtocol
	from msldap.commons.target import MSLDAPTarget
	from msldap.protocol.query import query_syntax_converter

	logger.setLevel(2)

	#from asn1crypto.core import ObjectIdentifier

	#o = ObjectIdentifier('1.2.840.113556.1.4.803')
	#print(o.dump())

	#from pprint import pprint
	#a = bytes.fromhex('3082026202010b63820235040f44433d746573742c44433d636f72700a01020a0103020100020100010100a050a9358116312e322e3834302e3131333535362e312e342e3830338212757365724163636f756e74436f6e74726f6c830734313934333034a217a415040e73414d4163636f756e744e616d653003820124308201bf040e6163636f756e7445787069726573040f62616450617373776f726454696d65040b626164507764436f756e740402636e0408636f646550616765040b636f756e747279436f6465040b646973706c61794e616d65041164697374696e677569736865644e616d650409676976656e4e616d650408696e697469616c73040a6c6173744c6f676f666604096c6173744c6f676f6e04126c6173744c6f676f6e54696d657374616d70040a6c6f676f6e436f756e7404046e616d65040b6465736372697074696f6e040e6f626a65637443617465676f7279040b6f626a656374436c617373040a6f626a6563744755494404096f626a656374536964040e7072696d61727947726f75704944040a7077644c617374536574040e73414d4163636f756e744e616d65040e73414d4163636f756e74547970650402736e0412757365724163636f756e74436f6e74726f6c0411757365725072696e636970616c4e616d65040b7768656e4368616e676564040b7768656e4372656174656404086d656d6265724f6604066d656d6265720414736572766963655072696e636970616c4e616d6504186d7344532d416c6c6f776564546f44656c6567617465546fa02430220416312e322e3834302e3131333535362e312e342e33313904083006020203e80400')
	#msg = LDAPMessage.load(a)
	#pprint.pprint(msg.native)
	
	#input()

	asyncio.run(amain())

	
	#qry = '(&(sAMAccountType=805306369)(sAMAccountName=test))'
	#qry = '(sAMAccountName=*)'
	#flt = LF.parse(qry)
	#print(flt)
	#print(flt.__dict__)
	#for f in flt.filters:
	#	print(f.__dict__)

	#x = convert(flt)
	#print(x)
	#print(x.native)

	#qry = '(sAMAccountType=0x100)'
	#flt = Filter.parse(qry)
	#print(flt)
	#print(flt.__dict__)
	#print(flt.filters)

			
			

		