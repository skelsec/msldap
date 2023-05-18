from msldap.protocol.utils import calcualte_length
from msldap.protocol.messages import LDAPMessage, AuthenticationChoice, protocolOp, BindResponse
from msldap import logger
import traceback
import asyncio

class LDAPRelayServerConnection:
	def __init__(self, settings, connection):
		self.settings = settings
		self.gssapi = settings.gssapi
		self.ntlm = self.gssapi.authentication_contexts['NTLMSSP - Microsoft NTLM Security Support Provider']
		self.connection = connection
		self.__auth_type = None
		self.__auth_iter = 0
	
	async def log_async(self, level, msg):
		if self.settings.log_q is not None:
			src = 'LDAPCON-%s:%s' % (self.client_ip, self.client_port)
			await self.settings.log_q.put((src, level, msg))
		else:
			logger.log(level, msg)

	async def terminate(self):
		self.handle_in_task.cancel()
	
	async def __handle_ldap_in(self):
		async for msg_data in self.connection.read():
			try:
				msg = LDAPMessage.load(msg_data)
				if msg['protocolOp']._choice == 0:
					await self.__bindreq(msg)
				else:
					raise Exception('Unknown LDAP message! %s' % msg.native)

			except Exception as e:
				await self.log_async(1, str(e))
				return

	async def __bindreq(self, msg):
		try:
			msg_id = msg.native['messageID']
			authdata_raw = msg.native['protocolOp']['authentication']
			if isinstance(authdata_raw, bytes) is True:
				self.__auth_type = 'NTLM'
				if self.__auth_iter == 0:
					t = {
						'resultCode' : 0,
						'matchedDN' : 'NTLM'.encode(),
						'diagnosticMessage' : b'',		
					}
					po = {'bindResponse' : BindResponse(t)}
					b= {
						'messageID' : msg_id,
						'protocolOp' : protocolOp(po),					
					}
					resp = LDAPMessage(b)
					await self.connection.write(resp.dump())
					self.__auth_iter += 1
					return
					
				else:
					resdata, to_conitnue, err = await self.ntlm.authenticate_relay_server(authdata_raw)
					if err is not None:
						raise err
					
					if resdata is None:
						t = {
						'resultCode' : 49,
						'matchedDN' : b'',
						'diagnosticMessage' : b'8009030C: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 52e, v4563\x00',		
						}
						po = {'bindResponse' : BindResponse(t)}
						b= {
							'messageID' : msg_id,
							'protocolOp' : protocolOp(po),
						}
						resp = LDAPMessage(b)

						await self.connection.write(resp.dump())

						await self.terminate()
						return
					
					t = {
						'resultCode' : 0,
						'matchedDN' : resdata,
						'diagnosticMessage' : b'',		
					}
					po = {'bindResponse' : BindResponse(t)}
					b= {
						'messageID' : msg_id,
						'protocolOp' : protocolOp(po),
					}
					resp = LDAPMessage(b)
					await self.connection.write(resp.dump())
					self.__auth_iter += 1
					return

			if isinstance(authdata_raw, dict) is True:
				self.__auth_type = 'GSSAPI'
				resdata, to_conitnue, err = await self.gssapi.authenticate_relay_server(authdata_raw['credentials'])
				if err is not None:
					raise err
				
				if resdata is None:
					t = {
						'resultCode' : 49,
						'matchedDN' : b'',
						'diagnosticMessage' : b'8009030C: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 52e, v4563\x00',		
					}
					po = {'bindResponse' : BindResponse(t)}
					b= {
						'messageID' : msg_id,
						'protocolOp' : protocolOp(po),
					}
					resp = LDAPMessage(b)

					await self.connection.write(resp.dump())

					await self.terminate()
					return

				t = {
					'resultCode' : 14,
					'matchedDN' : b'',
					'diagnosticMessage' : b'',
					'serverSaslCreds': 	resdata
				}
				po = {'bindResponse' : BindResponse(t)}
				b= {
					'messageID' : msg_id,
					'protocolOp' : protocolOp(po),					
				}
				resp = LDAPMessage(b)
				await self.connection.write(resp.dump())
				self.__auth_iter += 1
			
			else:
				raise Exception('Unknown auth method %s' % authdata_raw)

				
		except Exception as e:
			traceback.print_exc()
			return
	
	async def run(self):
		self.handle_in_task = asyncio.create_task(self.__handle_ldap_in())
		await self.handle_in_task