#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
# This is a failed attempt to simplify the SSPI integration.
# Sadly this doesnt work, as windows doesnt give the session key for some reason?
#

from winsspi.sspi import NegotiateSSPI, SSPIResult

class SPNEGO_SSPI:
	def __init__(self, settings):
		self.mode = 'CLIENT'
		self.settings = settings
		self.sspi = None
		self.username = None
		self.password = None
		self.target = None
		
		self.setup()
		
	def setup(self):
		if 'mode' in self.settings:
			self.mode = self.settings['mode']
		
		if 'username' in self.settings:
			self.username = self.settings['username']
			if 'password' in self.settings:
				self.password = self.settings['password']
				
		if 'target' in self.settings:
			self.username = self.settings['target']
	
		self.sspi = NegotiateSSPI()
		self.sspi.authGSSClientInit(self.target, client_name = self.username)
	
	def get_session_key(self):
		return self.sspi.get_session_key()
		
	async def encrypt(self, data, message_no):
		return await self.sspi.encrypt(data, message_no)

	async def decrypt(self, data, message_no):
		return await self.sspi.decrypt(data, message_no)
		
	async def authenticate(self, token, flags = None, seq_number = 0):
		try:
			if self.mode.upper() == 'CLIENT':
				res, data = self.sspi.authGSSClientStep(token)
				if res == SSPIResult.OK:
					return data[0][1], True
				elif res == SSPIResult.CONTINUE:
					return data[0][1], False
				else:
					raise Exception('SSPI errors')
					
			else:
				raise Exception('SERVER is not supported now')
		except Exception as e:
			import traceback
			traceback.print_exc()
	