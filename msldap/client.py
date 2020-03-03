import asyncio

from msldap import logger
from msldap.protocol.messages import LDAPMessage, BindRequest, \
	protocolOp, AuthenticationChoice, SaslCredentials, \
	SearchRequest, AttributeDescription, Filter, Filters
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
						print('Encrypted %s' % message_data)
						#removing size
						message_data = message_data[4:]
						try:
							message_data = await self.auth.decrypt(message_data, 0)
							print('Decrypted %s' % message_data)
						except:
							import traceback
							traceback.print_exc()
						
					elif self.__sign_messages is True:
						print('Signed %s' % message_data)
						message_data = message_data[4:]
						try:
							message_data = await self.auth.unsign(message_data)
							print('Unsinged %s' % message_data)
						except:
							import traceback
							traceback.print_exc()

				
				message = LDAPMessage.load(message_data)
				message = message.native
				self.message_table[message['messageID']] = message
				if message['messageID'] not in self.message_table_notify:
					self.message_table_notify[message['messageID']] = asyncio.Event()
				self.message_table_notify[message['messageID']].set()
		except Exception as e:
			for msgid in self.message_table_notify:
				self.message_table[msgid] = e
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
		print('Waiting for %s' % message_id)
		await self.message_table_notify[message_id].wait()
		#print(self.message_table)
		message = self.message_table[message_id]

		print('%s arrived!' % message_id)

		del self.message_table[message_id]
		del self.message_table_notify[message_id]

		return message

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
	
	async def search(self, base, filter, attributes, scope = 2, sizeLimit = 1000, typesOnly = False, derefAliases = 0, timeLimit = None):
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

		msg_id = await self.send_message(msg)
		res = await self.recv_message(msg_id)
		print(res)
		return res

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
	#auth_method = LDAPAuthProtocol.GSSAPI

	cred = MSLDAPCredential(domain, username, password , auth_method)
	target = MSLDAPTarget(ip)

	client = MSLDAPClientConnection(target, cred)
	await client.connect()
	await client.bind()
	
	#res = await client.search_test_2()
	#pprint.pprint(res)
	#search = bytes.fromhex('30840000007702012663840000006e043c434e3d3430392c434e3d446973706c6179537065636966696572732c434e3d436f6e66696775726174696f6e2c44433d746573742c44433d636f72700a01000a010002010002020258010100870b6f626a656374436c61737330840000000d040b6f626a656374436c617373')
	#msg = LDAPMessage.load(search)

	qry = '(sAMAccountName=*)'
	flt = query_syntax_converter(qry)
	res = await client.search(base.encode(), flt, ['*'.encode()])
	pprint.pprint(res)



if __name__ == '__main__':
	from msldap import logger
	from msldap.commons.credential import MSLDAPCredential, LDAPAuthProtocol
	from msldap.commons.target import MSLDAPTarget
	from msldap.protocol.utils import query_syntax_converter

	logger.setLevel(2)

	#from pprint import pprint
	#a = bytes.fromhex('30840000015802010163840000014f04000a01000a0100020100020178010100870b6f626a656374636c61737330840000012b0411737562736368656d61537562656e747279040d6473536572766963654e616d65040e6e616d696e67436f6e7465787473041464656661756c744e616d696e67436f6e746578740413736368656d614e616d696e67436f6e74657874041a636f6e66696775726174696f6e4e616d696e67436f6e746578740417726f6f74446f6d61696e4e616d696e67436f6e746578740410737570706f72746564436f6e74726f6c0414737570706f727465644c44415056657273696f6e0415737570706f727465644c444150506f6c69636965730417737570706f727465645341534c4d656368616e69736d73040b646e73486f73744e616d65040f6c646170536572766963654e616d65040a7365727665724e616d650415737570706f727465644361706162696c6974696573')
	#msg = LDAPMessage.load(a)
	#pprint(msg.native)
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

	

			
			

		