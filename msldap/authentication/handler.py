#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import copy
import asyncio
from msldap.commons.credential import LDAPAuthProtocol

# If multiplexor is used, the proxy is defining the auth as well!
#
#

class AuthHandler:
	def __init__(self, login_credential, target):
		self.login_credential = login_credential
		self.target = target

	def monkeypatch(self, auth_obj):
		#print('Monkey-patching ldap tp use SSPI module for NTLM auth!')
		import ldap3.utils.ntlm
		#monkey-patching NTLM client with winsspi's implementation
		ldap3.utils.ntlm.NtlmClient = auth_obj
		#return Connection(self._srv, user=self.login_credential.get_msuser(), password=self.login_credential.get_password(), authentication=NTLM)
		

	def select(self):
		if self.login_credential.auth_method == LDAPAuthProtocol.SSPI:
			try:
				from winsspi.sspi import LDAP3NTLMSSPI
			except ImportError:
				raise Exception('Failed to import winsspi module!')
			
			self.monkeypatch(LDAP3NTLMSSPI)
			return self.login_credential

		elif self.login_credential.auth_method in [LDAPAuthProtocol.MULTIPLEXOR, LDAPAuthProtocol.MULTIPLEXOR_SSL]:
			try:
				from multiplexor.operator import MultiplexorOperator
				from multiplexor.operator.external.sspi import LDAP3NTLMSSPI
			except ImportError:
				raise Exception('Failed to import multiplexor module!')

			async def create_sspi_server(connection_string, agent_id):
				try:
					#creating operator and connecting to multiplexor server
					self.operator = MultiplexorOperator(connection_string, reconnect_tries = 1)
					await self.operator.connect()
					#creating sspi server
					server_info = await self.operator.start_sspi(agent_id)
					await self.operator.terminate()
					return server_info
				except Exception as e:
					await self.operator.terminate()
					return e

			#creating connection string
			if self.login_credential.auth_method == LDAPAuthProtocol.MULTIPLEXOR:
				con_str = 'ws://%s:%s' % (self.login_credential.settings['host'][0], self.login_credential.settings['port'][0])
			else:
				con_str = 'wss://%s:%s' % (self.login_credential.settings['host'][0], self.login_credential.settings['port'][0])
			
			print('auth_connecting')
			agent_id = self.login_credential.settings['agentid'][0]
			#print(con_str)
			#input(agent_id)
			server_info = asyncio.run(create_sspi_server(con_str, agent_id))
			if isinstance(server_info, Exception):
				raise Exception('Failed to create socks proxy Reason: %s '% server_info)
			
			print('auth server info %s' % server_info)

			self.monkeypatch(LDAP3NTLMSSPI)
			##
			## Since this is a monkey patching object, we cannot control the input parameter count
			## We need to know the URL tho, and since the password filed is not used norally (no point using this object if you know the password)
			## The password filed is used to get the actual URL of the SSPI server
			##
			newcreds = copy.deepcopy(self.login_credential)
			newcreds.password = 'ws://%s:%s' % (server_info['listen_ip'], server_info['listen_port'])
			if newcreds.username is None:
				newcreds.username = '<CURRENT>'
			if newcreds.domain is None:
				newcreds.domain = '<CURRENT>'
			return newcreds

		return self.login_credential
