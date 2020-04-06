import asyncio


from msldap import logger
from msldap.commons.common import MSLDAPClientStatus
from msldap.protocol.messages import LDAPMessage, BindRequest, \
	protocolOp, AuthenticationChoice, SaslCredentials, \
	SearchRequest, AttributeDescription, Filter, Filters, \
	Controls, Control, SearchControlValue

from msldap.protocol.utils import calcualte_length
from msldap.protocol.typeconversion import convert_result, convert_attributes
from msldap.commons.authbuilder import AuthenticatorBuilder
from msldap.commons.credential import MSLDAP_GSS_METHODS
from msldap.network.selector import MSLDAPNetworkSelector
from msldap.commons.credential import LDAPAuthProtocol
from msldap.commons.target import LDAPProtocol
from asn1crypto.x509 import Certificate
from hashlib import sha256
from minikerberos.gssapi.channelbindings import ChannelBindingsStruct

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
		self.status = MSLDAPClientStatus.RUNNING
		self.lasterror = None

		self.message_id = 0
		self.message_table = {}
		self.message_table_notify = {}
		self.encryption_sequence_counter = 0x5364820 #0 #for whatever reason it's only used during encryption
		self.cb_data = None #for channel binding

	async def __handle_incoming(self):
		try:
			while True:
				message_data, err = await self.network.in_queue.get()
				if err is not None:
					logger.debug('Client terminating bc __handle_incoming got an error!')
					raise err
				
				#print('Incoming message data: %s' % message_data)
				if self.bind_ok is True:
					if self.__encrypt_messages is True:
						#removing size
						message_data = message_data[4:]
						try:
							# seq number doesnt matter here, a it's in the header
							message_data, err = await self.auth.decrypt(message_data, 0 )
							if err is not None:
								raise err
							#print('Decrypted %s' % message_data.hex())
							#print('Decrypted %s' % message_data)
						except:
							import traceback
							traceback.print_exc()
							raise
						
					elif self.__sign_messages is True:
						#print('Signed %s' % message_data)
						message_data = message_data[4:]
						try:
							message_data = await self.auth.unsign(message_data)
						#	print('Unsinged %s' % message_data)
						except:
							import traceback
							traceback.print_exc()
							raise
				
				
				msg_len = calcualte_length(message_data)
				msg_total_len = len(message_data)
				messages = []
				if msg_len == msg_total_len:
					message = LDAPMessage.load(message_data)
					messages.append(message)
				
				else:
					#print('multi-message!')
					while len(message_data) > 0:
						msg_len = calcualte_length(message_data)
						message = LDAPMessage.load(message_data[:msg_len])
						messages.append(message)
						
						message_data = message_data[msg_len:]

				message_id = messages[0]['messageID'].native
				if message_id not in self.message_table:
					self.message_table[message_id] = []
				self.message_table[message_id].extend(messages)
				if message_id not in self.message_table_notify:
					self.message_table_notify[message_id] = asyncio.Event()
				self.message_table_notify[message_id].set()
		
		except asyncio.CancelledError:
			self.status = MSLDAPClientStatus.STOPPED
			return

		except Exception as e:
			self.status = MSLDAPClientStatus.ERROR
			self.lasterror = e
			for msgid in self.message_table_notify:
				self.message_table[msgid] = [e]
				self.message_table_notify[msgid].set()
		
		self.status = MSLDAPClientStatus.STOPPED


	async def send_message(self, message):
		curr_msg_id = self.message_id
		self.message_id += 1

		message['messageID'] = curr_msg_id
		message_data = LDAPMessage(message).dump()

		if self.bind_ok is True:
			if self.__encrypt_messages is True:
				message_data, signature = await self.auth.encrypt(message_data, self.encryption_sequence_counter)
				message_data = signature + message_data
				message_data = len(message_data).to_bytes(4, byteorder = 'big', signed = False) + message_data
				self.encryption_sequence_counter += 1
			elif self.__sign_messages is True:
				signature = await self.auth.sign(message_data, self.encryption_sequence_counter)
				message_data = signature + message_data
				message_data = len(message_data).to_bytes(4, byteorder = 'big', signed = False) + message_data
				self.encryption_sequence_counter += 1
		
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
		
		# now processing channel binding options
		if self.target.proto == LDAPProtocol.SSL:
			certdata = self.network.get_peer_certificate()
			#cert = Certificate.load(certdata).native
			#print(cert)
			cb_struct = ChannelBindingsStruct()
			cb_struct.application_data = b'tls-server-end-point:' + sha256(certdata).digest()

			self.cb_data = cb_struct.to_bytes()

		self.handle_incoming_task = asyncio.create_task(self.__handle_incoming())
		logger.debug('Connection succsessful!')

	async def disconnect(self):
		logger.debug('Disconnecting!')
		self.bind_ok = False
		self.handle_incoming_task.cancel()
		await self.network.terminate()


	def __bind_success(self):
		"""
		Internal function invoked after bind finished. 
		Instructs the network layer that upcoming messages might be wrapped
		"""
		logger.debug('BIND Success!')
		self.bind_ok = True
		if self.creds.auth_method in MSLDAP_GSS_METHODS or self.creds.auth_method == LDAPAuthProtocol.SICILY:
			self.__sign_messages = self.auth.signing_needed()
			self.__encrypt_messages = self.auth.encryption_needed()
			if self.__encrypt_messages or self.__sign_messages:
				self.network.is_plain_msg = False

	async def bind(self):
		logger.debug('BIND in progress...')
		try:
			if self.creds.auth_method == LDAPAuthProtocol.SICILY:
				
				data, to_continue, err = await self.auth.authenticate(None)
				if err is not None:
					return None, err

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
				if isinstance(res, Exception):
					return False, res
				res = res.native
				if res['protocolOp']['resultCode'] != 'success':
					return False, Exception(
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
				if isinstance(res, Exception):
					return False, res
				res = res.native
				if res['protocolOp']['resultCode'] != 'success':
					return False, Exception(
						'BIND failed! Result code: "%s" Reason: "%s"' % (
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						))

				data, to_continue, err = await self.auth.authenticate(res['protocolOp']['matchedDN'])
				if err is not None:
					return None, err

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
				if isinstance(res, Exception):
					return False, res
				res = res.native
				if res['protocolOp']['resultCode'] != 'success':
					return False, Exception(
						'BIND failed! Result code: "%s" Reason: "%s"' % (
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						))
				

				self.__bind_success()
				return True, None

			elif self.creds.auth_method == LDAPAuthProtocol.SIMPLE:
				pw = b''
				if self.auth.password != None:
					pw = self.auth.password.encode()

				user = b''
				if self.auth.username != None:
					user = self.auth.username.encode()

				auth = {
					'simple' : pw
				}

				bindreq = {
					'version' : 3,
					'name': user,
					'authentication': AuthenticationChoice(auth), 
				}

				br = { 'bindRequest' : BindRequest( bindreq	)}
				msg = { 'protocolOp' : protocolOp(br)}
					
				msg_id = await self.send_message(msg)
				res = await self.recv_message(msg_id)
				res = res[0]
				if isinstance(res, Exception):
					return False, res
				res = res.native
				if res['protocolOp']['resultCode'] == 'success':
					self.__bind_success()
					return True, None
				
				else:
					return False, Exception(
						'BIND failed! Result code: "%s" Reason: "%s"' % (
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						))

			elif self.creds.auth_method in MSLDAP_GSS_METHODS:
				challenge = None
				while True:
					try:
						data, to_continue, err = await self.auth.authenticate(challenge, cb_data = self.cb_data)
						if err is not None:
							raise err
					except Exception as e:
						return False, e
					
					sasl = {
						'mechanism' : 'GSS-SPNEGO'.encode(),
						'credentials' : data,
					}
					auth = {
						'sasl' : SaslCredentials(sasl)
					}

					bindreq = {
						'version' : 3,
						'name': b'',
						'authentication': AuthenticationChoice(auth), 
					}

					br = { 'bindRequest' : BindRequest( bindreq	)}
					msg = { 'protocolOp' : protocolOp(br)}
					
					msg_id = await self.send_message(msg)
					res = await self.recv_message(msg_id)
					res = res[0]
					if isinstance(res, Exception):
						return False, res
					res = res.native
					if res['protocolOp']['resultCode'] == 'success':
						if 'serverSaslCreds' in res['protocolOp']:
							data, _, err = await self.auth.authenticate(res['protocolOp']['serverSaslCreds'], cb_data = self.cb_data)
							if err is not None:
								return False, err

						self.encryption_sequence_counter = self.auth.get_seq_number()
						self.__bind_success()

						return True, None

					elif res['protocolOp']['resultCode'] == 'saslBindInProgress':
						challenge = res['protocolOp']['serverSaslCreds']
						continue

					else:
						return False, Exception(
							'BIND failed! Result code: "%s" Reason: "%s"' % (
								res['protocolOp']['resultCode'], 
								res['protocolOp']['diagnosticMessage']
							))
					
					#print(res)
		except Exception as e:
			return False, e
	
	async def search(self, base, filter, attributes, search_scope = 2, paged_size = 1000, typesOnly = False, derefAliases = 0, timeLimit = None, controls = None, return_done = False):
		"""
		This function is a generator!!!!! Dont just call it but use it with "async for"
		"""
		if self.status != MSLDAPClientStatus.RUNNING:
			yield None, Exception('Connection not running! Probably encountered an error')
			return
		try:
			if timeLimit is None:
				timeLimit = 600 #not sure
			
			searchreq = {
				'baseObject' : base,
				'scope': search_scope,
				'derefAliases': derefAliases, 
				'sizeLimit': paged_size,
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
					msg_type = message['protocolOp'].name
					message = message.native
					if msg_type == 'searchResDone':
						#print(message)
						#print('BREAKING!')
						if return_done is True:
							yield (message, None)
						break
					
					elif msg_type == 'searchResRef':
						#TODO: Check if we need to deal with this further
						continue

					if return_done is True:
						yield (message, None)
					else:
						yield (convert_result(message['protocolOp']), None)
				else:
					continue
				
				break
		
		except Exception as e:
			yield (None, e)

	async def pagedsearch(self, base, filter, attributes, search_scope = 2, paged_size = 1000, typesOnly = False, derefAliases = 0, timeLimit = None, controls = None):
		if self.status != MSLDAPClientStatus.RUNNING:
			yield None, Exception('Connection not running! Probably encountered an error')
			return
		try:
			cookie = b''
			while True:
				
				ctrl_list_temp = [
					Control({
						'controlType' : b'1.2.840.113556.1.4.319',
						'controlValue': SearchControlValue({
							'size' : paged_size,
							'cookie': cookie
						}).dump()
					})
				]
				if controls is not None:
					ctrl_list_temp.extend(controls)
				
				ctrs = Controls(
					ctrl_list_temp
				)


				async for res, err in self.search(
					base, 
					filter, 
					attributes, 
					search_scope = search_scope, 
					paged_size=paged_size, 
					typesOnly=typesOnly, 
					derefAliases=derefAliases, 
					timeLimit=timeLimit, 
					controls = ctrs,
					return_done = True
					):
						if err is not None:
							yield (None, err)
							return

						if 'resultCode' in res['protocolOp']:
							for control in res['controls']:
								if control['controlType'] == b'1.2.840.113556.1.4.319':
									try:
										cookie = SearchControlValue.load(control['controlValue']).native['cookie']
									except Exception as e:
										raise e
									break
							else:
								raise Exception('SearchControl missing from server response!')
						else:
							yield (convert_result(res['protocolOp']), None)

				if cookie == b'':
					break
		
		except Exception as e:
			yield (None, e)


	async def get_serverinfo(self):
		if self.status != MSLDAPClientStatus.RUNNING:
			return None, Exception('Connection not running! Probably encountered an error')

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
		res = res[0]
		if isinstance(res, Exception):
			return None, res
		
		#print('res')
		#print(res)
		return convert_attributes(res.native['protocolOp']['attributes']), None


async def amain():
	import traceback
	from msldap.commons.url import MSLDAPURLDecoder

	base = 'DC=TEST,DC=CORP'

	#ip = 'WIN2019AD'
	#domain = 'TEST'
	#username = 'victim'
	#password = 'Passw0rd!1'
	##auth_method = LDAPAuthProtocol.SICILY
	#auth_method = LDAPAuthProtocol.SIMPLE

	#cred = MSLDAPCredential(domain, username, password , auth_method)
	#target = MSLDAPTarget(ip)
	#target.dc_ip = '10.10.10.2'
	#target.domain = 'TEST'

	url = 'ldap+kerberos-password://test\\victim:Passw0rd!1@WIN2019AD/?dc=10.10.10.2'

	dec = MSLDAPURLDecoder(url)
	cred = dec.get_credential()
	target = dec.get_target()

	print(cred)
	print(target)

	input()

	client = MSLDAPClientConnection(target, cred)
	await client.connect()
	res, err = await client.bind()
	if err is not None:
		raise err

	#res = await client.search_test_2()
	#pprint.pprint(res)
	#search = bytes.fromhex('30840000007702012663840000006e043c434e3d3430392c434e3d446973706c6179537065636966696572732c434e3d436f6e66696775726174696f6e2c44433d746573742c44433d636f72700a01000a010002010002020258010100870b6f626a656374436c61737330840000000d040b6f626a656374436c617373')
	#msg = LDAPMessage.load(search)

	
	
	qry = r'(sAMAccountName=*)' #'(userAccountControl:1.2.840.113556.1.4.803:=4194304)' #'(sAMAccountName=*)'
	#qry = r'(sAMAccountType=805306368)'
	#a = query_syntax_converter(qry)
	#print(a.native)
	#input('press bacon!')
	
	flt = query_syntax_converter(qry)
	i = 0
	async for res, err in client.pagedsearch(base.encode(), flt, ['*'.encode()], derefAliases=3, typesOnly=False):
		if err is not None:
			print('Error!')
			raise err
		i += 1
		if i % 1000 == 0:
			print(i)
		#pprint.pprint(res)

	await client.disconnect()



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

			
			

		