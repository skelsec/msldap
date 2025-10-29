import asyncio
from typing import List, Dict
import ssl

from msldap import logger
from msldap.commons.common import MSLDAPClientStatus
from .commons.target import MSLDAPTarget
from msldap.protocol.messages import LDAPMessage, BindRequest, \
	protocolOp, AuthenticationChoice, SaslCredentials, \
	SearchRequest, AttributeDescription, Filter, Filters, \
	Controls, Control, SearchControlValue, AddRequest, \
	ModifyRequest, DelRequest, ExtendedRequest, ExtendedResponse

from msldap.protocol.utils import calcualte_length
from msldap.protocol.typeconversion import convert_result, convert_attributes, encode_attributes, encode_changes
from msldap.protocol.query import escape_filter_chars, query_syntax_converter
from msldap.commons.authbuilder import get_auth_context
from msldap.network.packetizer import LDAPPacketizer
from asysocks.unicomm.common.target import UniProto
from msldap.commons.exceptions import LDAPBindException, LDAPAddException, LDAPModifyException, LDAPDeleteException, LDAPSearchException
from hashlib import sha256
from asysocks.unicomm.client import UniClient
from asyauth.common.constants import asyauthProtocol
from asyauth.common.credentials import UniCredential
from asyauth.common.winapi.constants import ISC_REQ

class MSLDAPClientConnection:
	def __init__(self, target:MSLDAPTarget, credential:UniCredential, auth=None):
		self.target = target
		self.credential = credential
		if auth is not None:
			self.auth = auth
		else:
			self.auth = get_auth_context(self.credential)

		self.connected = False
		self.bind_ok = False
		self.is_anon = False
		self.__sign_messages = False
		self.__encrypt_messages = False
		self.network = None
		self.connection_closed_evt = None

		self.handle_incoming_task = None
		self.status = MSLDAPClientStatus.RUNNING
		self.lasterror = None

		self.message_id = 0
		self.message_table = {}
		self.message_table_notify = {}
		self.encryption_sequence_counter = 0 # this will be set by the inderlying auth algo
		self.cb_data = None #for channel binding
		self._disable_channel_binding = False # putting it here for scanners to be able to turn it off
		self._disable_signing = False
		self._null_channel_binding = False

		if self.credential.protocol == asyauthProtocol.NONE:
			self.is_anon = True
	
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await asyncio.wait_for(self.disconnect(), timeout = 1)

	async def __handle_incoming(self):
		try:
			
			async for message_data in self.network.read():
				if message_data is None:
					break	
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

				###### EMERGENCY DEBUG ######
				#print('DEBUG: Received message: %s' % messages)
				###### EMERGENCY DEBUG ######

				message_id = messages[0]['messageID'].native
				if message_id not in self.message_table:
					self.message_table[message_id] = []
				self.message_table[message_id].extend(messages)
				if message_id not in self.message_table_notify:
					self.message_table_notify[message_id] = asyncio.Event()
				self.message_table_notify[message_id].set()
		
			raise Exception('Connection closed!')
		except asyncio.CancelledError:
			self.status = MSLDAPClientStatus.STOPPED
			return

		except Exception as e:
			self.status = MSLDAPClientStatus.ERROR
			self.lasterror = e
			for msgid in self.message_table_notify:
				self.message_table[msgid] = [e]
				self.message_table_notify[msgid].set()
		
		finally:
			if self.connection_closed_evt is not None:
				self.connection_closed_evt.set()
			self.status = MSLDAPClientStatus.STOPPED



	async def send_message(self, message:Dict[str, object]):

		###### EMERGENCY DEBUG ######
		#print('DEBUG: Sending message: %s' % message)
		###### EMERGENCY DEBUG ######

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
		await self.network.write(message_data)

		return curr_msg_id

	async def recv_message(self, message_id:int):
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

	def get_extra_info(self):
		try:
			ntlm_data = self.auth.get_extra_info()
			if ntlm_data is not None:
				ntlm_data = ntlm_data.to_dict()
		except:
			traceback.print_exc()
			ntlm_data = None
		return {'ntlm_data' : ntlm_data}

	async def connect(self):
		"""
		Connects to the remote server. Establishes the session, but doesn't perform binding.
		This function MUST be called first before the `bind` operation.

		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		try:
			logger.debug('Connecting!')
			self.connection_closed_evt = asyncio.Event()
			packetizer = LDAPPacketizer()
			client = UniClient(self.target, packetizer)
			self.network = await asyncio.wait_for(client.connect(), timeout=self.target.timeout)
			
			# now processing channel binding options
			if self.target.protocol == UniProto.CLIENT_SSL_TCP and self._disable_channel_binding is False:
				if self._null_channel_binding is True:
					self.cb_data = b'tls-server-end-point:' + sha256(b'').digest()
				else:
					certdata = self.network.get_peer_certificate()
					self.cb_data = b'tls-server-end-point:' + sha256(certdata).digest()

			self.handle_incoming_task = asyncio.create_task(self.__handle_incoming())
			self.status = MSLDAPClientStatus.CONNECTED
			logger.debug('Connection succsessful!')
			return True, None
		except Exception as e:
			return False, e

	async def disconnect(self):
		"""
		Tears down the connection.

		:return: Nothing
		:rtype: None
		"""

		logger.debug('Disconnecting!')
		self.bind_ok = False
		if self.connection_closed_evt is not None:
			self.connection_closed_evt.set()
		
		if self.network is not None:
			await self.network.close()
			await asyncio.sleep(0)
		
		if self.handle_incoming_task is not None:
			self.handle_incoming_task.cancel()


	def __bind_success(self):
		"""
		Internal function invoked after bind finished. 
		Instructs the network layer that upcoming messages might be wrapped
		"""
		logger.debug('BIND Success!')
		self.bind_ok = True
		self.status = MSLDAPClientStatus.RUNNING
		if self.credential.protocol in [asyauthProtocol.NTLM, asyauthProtocol.KERBEROS, asyauthProtocol.SICILY]:
			self.__sign_messages = self.auth.signing_needed()
			self.__encrypt_messages = self.auth.encryption_needed()
			if self.__encrypt_messages or self.__sign_messages:
				self.network.packetizer.is_plain_msg = False

	async def bind(self):
		"""
		Performs the bind operation.
		This is where the authentication happens. Remember to call `connect` before this function!

		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		if self.status != MSLDAPClientStatus.CONNECTED:
			raise Exception("Connect to the LDAP server before binding.")
		logger.debug('BIND in progress...')
		try:
			if self.credential.protocol == asyauthProtocol.SICILY:
				flags = ISC_REQ.CONNECTION|ISC_REQ.CONFIDENTIALITY|ISC_REQ.INTEGRITY
				if self.target.protocol == UniProto.CLIENT_SSL_TCP:
					flags = ISC_REQ.CONNECTION
				
				# this switch is for the case when we are using NTLM and we want to disable signing
				# useful for testing if the server supports it
				if self._disable_signing is True:
					flags = ISC_REQ.CONNECTION
				
				logger.debug('SICILY bind with flags: %s' % flags)
				
				data, to_continue, err = await self.auth.authenticate(None, spn=self.target.to_target_string(), flags=flags, cb_data = self.cb_data)
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
					return False, LDAPBindException(
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						)
				
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
					return False, LDAPBindException(
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						)

				data, to_continue, err = await self.auth.authenticate(res['protocolOp']['matchedDN'], spn=self.target.to_target_string(), cb_data = self.cb_data)
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
					return False, LDAPBindException(
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						)
				

				self.__bind_success()
				return True, None

			elif self.credential.protocol == asyauthProtocol.SIMPLE:
				pw = b''
				if self.auth.secret != None:
					pw = self.auth.secret.encode()

				user = b''
				if self.auth.username != None:
					user = self.auth.username.encode()
				if user == b'':
					self.is_anon = True
				
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
					return False, LDAPBindException(
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						)

			elif self.credential.protocol in [asyauthProtocol.NTLM, asyauthProtocol.KERBEROS]:
				challenge = None
				while True:
					try:
						flags = ISC_REQ.CONNECTION|ISC_REQ.CONFIDENTIALITY|ISC_REQ.INTEGRITY
						if self.target.protocol == UniProto.CLIENT_SSL_TCP:
							flags = ISC_REQ.CONNECTION
						
						# this switch is for the case when we want to disable signing
						# useful for testing if the server supports it
						if self._disable_signing is True:
							flags = ISC_REQ.CONNECTION
						
						data, to_continue, err = await self.auth.authenticate(challenge, cb_data = self.cb_data, spn=self.target.to_target_string(), flags=flags)
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
							data, _, err = await self.auth.authenticate(res['protocolOp']['serverSaslCreds'], cb_data = self.cb_data, spn=self.target.to_target_string(), flags=flags)
							if err is not None:
								return False, err

						if self.auth.encryption_needed() is True or self.auth.signing_needed() is True:
							self.encryption_sequence_counter = self.auth.get_seq_number()
						self.__bind_success()

						return True, None

					elif res['protocolOp']['resultCode'] == 'saslBindInProgress':
						challenge = res['protocolOp']['serverSaslCreds']
						continue

					else:
						return False, LDAPBindException(
								res['protocolOp']['resultCode'], 
								res['protocolOp']['diagnosticMessage']
							)
			elif self.credential.protocol == asyauthProtocol.SSL:
				if self.target.protocol == UniProto.CLIENT_SSL_TCP:
					# NOTE! If LDAPS is used with SSL authentication, EXTERNAL bid is NOT needed!
					# Again, it is NOT needed!
					# If the handshake is successful, the client is authenticated (but sometimes not?)
					self.__bind_success()
					return True, None
				elif self.target.protocol == UniProto.CLIENT_TCP:
					_, err = await self.starttls()
					if err is not None:
						return False, err
					
					sasl = {
						'mechanism' : 'EXTERNAL'.encode(),
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
					if isinstance(res[0], Exception):
						return False, res[0]
					resp = res[0].native['protocolOp']
					if resp['resultCode'] != 'success':
						#startls refused :(
						return False, LDAPBindException(
								resp['resultCode'], 
								resp['diagnosticMessage']
							)
					self.__bind_success()
					return True, None
				
				return False, Exception('Not implemented: %s' % self.credential.protocol.name)
					
			else:
				raise Exception('Not implemented authentication method: %s' % self.credential.protocol.name)
			
		except Exception as e:
			await self.disconnect()
			return False, e

	async def starttls(self):
		try:
			# https://www.ietf.org/rfc/rfc2830.txt
			ext = {
				'requestName': b'1.3.6.1.4.1.1466.20037', 
			}
			br = { 'extendedReq' : ExtendedRequest(ext)}
			msg = { 'protocolOp' : protocolOp(br)}
			msg_id = await self.send_message(msg)
			res = await self.recv_message(msg_id)
			if isinstance(res[0], Exception):
				return False, res[0]
			resp = res[0].native['protocolOp']
			if resp['resultCode'] != 'success':
				#startls refused :(
				return False, LDAPBindException(
						resp['resultCode'], 
						resp['diagnosticMessage']
					)
			self.handle_incoming_task.cancel()
			await asyncio.sleep(0)
			await self.network.wrap_ssl(self.target.get_ssl_context(ssl.PROTOCOL_TLS_CLIENT))
			self.handle_incoming_task = asyncio.create_task(self.__handle_incoming())
			self.status = MSLDAPClientStatus.CONNECTED
			await asyncio.sleep(0)
			return True, None
		except Exception as e:
			print(e)
			return False, e

	async def add(self, entry:str, attributes:Dict[str, object]):
		"""
		Performs the add operation.
		
		:param entry: The DN of the object to be added
		:type entry: str
		:param attributes: Attributes to be used in the operation
		:type attributes: dict
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		try:
			req = {
				'entry' : entry.encode(),
				'attributes' : encode_attributes(attributes)
			}
			logger.debug(req)
			br = { 'addRequest' : AddRequest(req)}
			msg = { 'protocolOp' : protocolOp(br)}
			
			msg_id = await self.send_message(msg)
			results = await self.recv_message(msg_id)
			if isinstance(results[0], Exception):
				return False, results[0]
			
			for message in results:
				msg_type = message['protocolOp'].name
				message = message.native
				if msg_type == 'addResponse':
					if message['protocolOp']['resultCode'] != 'success':
						return False, LDAPAddException(
							entry,
							message['protocolOp']['resultCode'],
							message['protocolOp']['diagnosticMessage']
						)

			return True, None
		except Exception as e:
			return False, e

	async def modify(self, entry:str, changes:Dict[str, object], controls:List[Control] = None, encode=True,):
		"""
		Performs the modify operation.
		
		:param entry: The DN of the object whose attributes are to be modified
		:type entry: str
		:param changes: Describes the changes to be made on the object. Must be a dictionary of the following format: {'attribute': [('change_type', [value])]}
		:type changes: dict
		:param controls: additional controls to be passed in the query
		:type controls: List[class:`Control`] 
		:param encode: encode the changes provided before sending them to the server
    	:type encode: bool

		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		try:
			req = {
				'object' : entry.encode(),
				'changes' : encode_changes(changes, encode)
			}
			br = { 'modifyRequest' : ModifyRequest(req)}
			msg = { 'protocolOp' : protocolOp(br)}
			if controls is not None:
				msg['controls'] = controls
			
			msg_id = await self.send_message(msg)
			results = await self.recv_message(msg_id)
			if isinstance(results[0], Exception):
				return False, results[0]
			
			for message in results:
				msg_type = message['protocolOp'].name
				message = message.native
				if msg_type == 'modifyResponse':
					if message['protocolOp']['resultCode'] != 'success':
						return False, LDAPModifyException(
							entry,
							message['protocolOp']['resultCode'],
							message['protocolOp']['diagnosticMessage']
						)

			return True, None
		except Exception as e:
			return False, e

	async def delete(self, entry:str):
		"""
		Performs the delete operation.
		
		:param entry: The DN of the object to be deleted
		:type entry: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		try:
			br = { 'delRequest' : DelRequest(entry.encode())}
			msg = { 'protocolOp' : protocolOp(br)}
			
			msg_id = await self.send_message(msg)
			results = await self.recv_message(msg_id)
			if isinstance(results[0], Exception):
				return False, results[0]
			
			for message in results:
				msg_type = message['protocolOp'].name
				message = message.native
				if msg_type == 'delResponse':
					if message['protocolOp']['resultCode'] != 'success':
						return False, LDAPDeleteException(
							entry,
							message['protocolOp']['resultCode'],
							message['protocolOp']['diagnosticMessage']
						)

			return True, None
		except Exception as e:
			return False, e
	
	async def search(self, base:str, query:str, attributes:List[bytes], search_scope:int = 2, size_limit:int = 1000, types_only:bool = False, derefAliases:int = 0, timeLimit:int = None, controls:List[Control] = None, return_done:bool = False):
		"""
		Performs the search operation.
		
		:param base: base tree on which the search should be performed
		:type base: str
		:param query: filter query that defines what should be searched for
		:type query: str
		:param attributes: a list of attributes to be included in the response
		:type attributes: List[bytes]
		:param search_scope: Specifies the search operation's scope. Default: 2 (Subtree)
		:type search_scope: int
		:param types_only: indicates whether the entries returned should include attribute types only or both types and values. Default: False (both)
		:type types_only: bool
		:param size_limit: Size limit of result elements per query. Default: 1000
		:type size_limit: int
		:param derefAliases: Specifies the behavior on how aliases are dereferenced. Default: 0 (never)
		:type derefAliases: int
		:param timeLimit: Maximum time the search should take. If time limit reached the server SHOULD return an error
		:type timeLimit: int
		:param controls: additional controls to be passed in the query
		:type controls: List[class:`Control`]
		:param return_done: Controls wether the final 'done' LDAP message should be returned, or just the actual results
		:type return_done: bool

		:return: Async generator which yields (`LDAPMessage`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`LDAPMessage`, :class:`Exception`)]
		"""

		try:
			if self.status == MSLDAPClientStatus.CONNECTED:
				raise Exception('Connected, but not bound.')
			if self.status != MSLDAPClientStatus.RUNNING:
				raise Exception('Connection not running! Probably encountered an error')
		
			if timeLimit is None:
				timeLimit = 600 #not sure

			flt = query_syntax_converter(query)
			
			searchreq = {
				'baseObject' : base.encode(),
				'scope': search_scope,
				'derefAliases': derefAliases, 
				'sizeLimit': size_limit,
				'timeLimit': timeLimit,
				'typesOnly': types_only,
				'filter': flt,
				'attributes': attributes,
			}

			br = { 'searchRequest' : SearchRequest( searchreq	)}
			msg = { 'protocolOp' : protocolOp(br)}
			if controls is not None:
				msg['controls'] = controls

			msg_id = await self.send_message(msg)
			
			while True:
				results = await self.recv_message(msg_id)
				if len(results) > 0 and isinstance(results[0], Exception):
					raise results[0]
				
				for message in results:
					msg_type = message['protocolOp'].name
					message = message.native
					if msg_type == 'searchResDone':
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

	async def pagedsearch(self, base:str, query:str, attributes:List[bytes], search_scope:int = 2, size_limit:int = 1000, typesOnly:bool = False, derefAliases:bool = 0, timeLimit:int = None, controls:List[Control] = None, rate_limit:int = 0):
		"""
		Paged search is the same as the search operation and uses it under the hood. Adds automatic control to read all results in a paged manner.
		
		:param base: base tree on which the search should be performed
		:type base: str
		:param query: filter query that defines what should be searched for
		:type query: str
		:param attributes: a list of attributes to be included in the response
		:type attributes: List[bytes]
		:param search_scope: Specifies the search operation's scope. Default: 2 (Subtree)
		:type search_scope: int
		:param types_only: indicates whether the entries returned should include attribute types only or both types and values. Default: False (both)
		:type types_only: bool
		:param size_limit: Size limit of result elements per query. Default: 1000
		:type size_limit: int
		:param derefAliases: Specifies the behavior on how aliases are dereferenced. Default: 0 (never)
		:type derefAliases: int
		:param timeLimit: Maximum time the search should take. If time limit reached the server SHOULD return an error
		:type timeLimit: int
		:param controls: additional controls to be passed in the query
		:type controls: dict
		:param rate_limit: time to sleep bwetween each query
		:type rate_limit: float
		:return: Async generator which yields (`dict`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`dict`, :class:`Exception`)]
		"""
		
		try:
			if self.status == MSLDAPClientStatus.CONNECTED:
				raise Exception('Connected, but not bound.')
			if self.status != MSLDAPClientStatus.RUNNING:
				raise Exception('Connection not running! Probably encountered an error')
		
			cookie = b''
			while True:
				await asyncio.sleep(rate_limit)
				ctrl_list_temp = [
					Control({
						'controlType' : b'1.2.840.113556.1.4.319',
						'controlValue': SearchControlValue({
							'size' : size_limit,
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
					query, 
					attributes, 
					search_scope = search_scope, 
					size_limit=size_limit, 
					types_only=typesOnly, 
					derefAliases=derefAliases, 
					timeLimit=timeLimit, 
					controls = ctrs,
					return_done = True
					):
						if err is not None:
							yield (None, err)
							return
						
						if 'resultCode' in res['protocolOp']:
							if res['protocolOp']['resultCode'] != 'success':
								raise LDAPSearchException(res['protocolOp']['resultCode'], res['protocolOp']['diagnosticMessage'])
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

	async def whoami(self):
		if self.status != MSLDAPClientStatus.RUNNING:
			return None, Exception('Connection not running! Probably encountered an error')
		
		ext = {
			'requestName': b'1.3.6.1.4.1.4203.1.11.3',
		}
		br = { 'extendedReq' : ExtendedRequest(ext)}
		msg = { 'protocolOp' : protocolOp(br)}

		msg_id = await self.send_message(msg)
		res = await self.recv_message(msg_id)
		res = res[0]
		if isinstance(res, Exception):
			return None, res
		if res.native['protocolOp']['resultCode'] != 'success':
			return False, LDAPBindException(
					res['protocolOp']['resultCode'], 
					res['protocolOp']['diagnosticMessage']
				)
		return res.native['protocolOp']['responseValue'].decode(), None
		


	async def get_serverinfo(self):
		if self.status not in [MSLDAPClientStatus.CONNECTED, MSLDAPClientStatus.RUNNING]:
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
		
		if 'attributes' not in res.native['protocolOp']:
			return None, None
		return convert_attributes(res.native['protocolOp']['attributes']), None
