#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import copy
from msldap.authentication.spnego.asn1_structs import *

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/d4f2b41c-5f9e-4e11-98d0-ade76467095d


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/94ccc4f8-d224-495f-8d31-4f58d1af598e
## SPNEGO has been assigned the following object identifier (OID): so.org.dod.internet.security.mechanism.snego (1.3.6.1.5.5.2)

class SPNEGO:
	def __init__(self, mode = 'CLIENT'):
		self.mode = mode
		self.authentication_contexts = {}
		self.original_authentication_contexts = {}
		self.selected_authentication_context = None
		self.selected_mechtype = None
		self.iteration_ctr = 0
	
	def get_copy(self):
		spnego = SPNEGO()
		for ctx_name in self.list_original_conexts():
			spnego.add_auth_context(ctx_name, self.get_original_context(ctx_name))
		return spnego
		
	def list_original_conexts(self):
		"""
		Returns a list of authentication context names available to the SPNEGO authentication.
		"""
		return list(self.original_authentication_contexts.keys())
		
	def get_original_context(self, ctx_name):
		"""
		Returns a copy of the original (not used) authentication context sp[ecified by name.
		You may use this ctx to perform future authentication, as it has the user credentials
		"""
		return copy.deepcopy(self.original_authentication_contexts[ctx_name])
	
	def signing_needed(self):
		return self.selected_authentication_context.signing_needed()
	
	def encryption_needed(self):
		return self.selected_authentication_context.encryption_needed()

	async def unsign(self, data):
		#TODO: IMPLEMENT THIS
		return data

	async def sign(self, data, message_no, direction='init'):
		return await self.selected_authentication_context.sign(data, message_no, direction=direction)
		
	async def encrypt(self, data, message_no):
		return await self.selected_authentication_context.encrypt(data, message_no)

	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		return await self.selected_authentication_context.decrypt(data, message_no, direction=direction, auth_data=auth_data)
		
	def add_auth_context(self, name, ctx):
		"""
		Add an authentication context to the given authentication context name.
		Valid names are:
			'NTLMSSP - Microsoft NTLM Security Support Provider'
			'MS KRB5 - Microsoft Kerberos 5'
			'KRB5 - Kerberos 5'
			'KRB5 - Kerberos 5 - User to User'
			'NEGOEX - SPNEGO Extended Negotiation Security Mechanism'
			
		Context MUST be already set up!
		"""
		self.authentication_contexts[name] = ctx
		self.original_authentication_contexts[name] = copy.deepcopy(ctx)
		
	def select_common_athentication_type(self, mech_types):
		for auth_type_name in self.authentication_contexts:
			if auth_type_name in mech_types:
				print(auth_type_name)
				return auth_type_name, self.authentication_contexts[auth_type_name]
				
		return None, None
		
	async def process_ctx_authenticate(self, token_data, include_negstate = False, flags = None, seq_number = 0, is_rpc = False):
		result, to_continue = await self.selected_authentication_context.authenticate(token_data, flags = flags, seq_number = seq_number, is_rpc = is_rpc)
		if not result:
			return None, False
		response = {}
		if include_negstate == True:
			if to_continue == True:
				response['negState'] = NegState('accept-incomplete')
			else:
				response['negState'] = NegState('accept-completed')
		
		response['responseToken'] = result
		return response, to_continue
		
	def get_extra_info(self):
		if hasattr(self.selected_authentication_context, 'get_extra_info'):
			return self.selected_authentication_context.get_extra_info()
		return None
	
	def get_session_key(self):
		return self.selected_authentication_context.get_session_key()

	def get_mechtypes_list(self):
		neghint = {'hintName':'not_defined_in_RFC4178@please_ignore'}
		tokinit = {
			'mechTypes': [MechType(mt) for mt in self.authentication_contexts],
			'negHints': NegHints(neghint),
		}

		negtoken = NegotiationToken({'negTokenInit':NegTokenInit2(tokinit)})
		#spnego = GSS_SPNEGO({'NegotiationToken':negtoken})
		return GSSAPI({'type': GSSType('1.3.6.1.5.5.2'), 'value':negtoken}).dump()
	
	async def authenticate(self, token, flags = None, seq_number = 0, is_rpc = False):
		"""
		This function is called (multiple times) during negotiation phase of a protocol to determine hich auth mechanism to be used
		Token is a byte array that is an ASN1 NegotiationToken structure.
		"""
		
		if self.mode == 'SERVER':
			if self.selected_authentication_context is None:
				gss = GSSAPI.load(token).native
				negtoken = gss['value']
				if len(negtoken['mechTypes']) == 1:
					self.selected_mechtype = negtoken['mechTypes'][0]
					if negtoken['mechTypes'][0] == 'NTLMSSP - Microsoft NTLM Security Support Provider':
						self.selected_authentication_context = self.authentication_contexts[negtoken['mechTypes'][0]]


				else:
					raise Exception('This path is not yet implemented')
					#self.selected_mechtype, self.selected_authentication_context = self.select_common_athentication_type(neg_token.mechTypes)
					#if self.selected_mechtype is None:
					#	raise Exception('Failed to select common authentication mechanism! Client sent: %s We have %s' % ())
				#
				#	##server offered multiple auth types, we must choose one
				#	#response = {}
				#	#response['negState'] = NegState('accept-incomplete')
				#	#response['supportedMech'] = MechType(self.selected_mechtype)
				#	#		
					#return NegTokenResp(response).dump(), True


			if self.selected_authentication_context is not None:
				response, to_continue = await self.process_ctx_authenticate(negtoken['mechToken'], flags = flags, seq_number = seq_number, is_rpc = is_rpc, include_negstate = True)
				if self.iteration_ctr == 0:
					response['supportedMech'] = MechType(self.selected_mechtype)
				negtoken = NegotiationToken({'negTokenResp':NegTokenResp(response)})
					
					
				#spnego = GSS_SPNEGO({'NegotiationToken':negtoken})

				self.iteration_ctr += 1
				#return GSSAPI({'type': GSSType('1.3.6.1.5.5.2'), 'value':negtoken}).dump(), to_continue
				return negtoken.dump(), to_continue

			#neg_token_raw = NegotiationToken.load(token)
			#neg_token = neg_token_raw.native
			#if isinstance(neg_token_raw, NegTokenInit2):
			#	if selected_authentication_context is not None:
			#		raise Exception('Authentication context already selected, but Client sent NegTokenInit2')
			#	
			#	if len(neg_token.mechTypes) == 1:
			#		#client only sent 1 negotiation token type, we either support it or raise exception
			#		if neg_token.mechTypes[0] not in self.authentication_contexts:
			#			raise Exception('Client sent %s auth mechanism but we dont have that set up!' % neg_token.mechTypes[0])
			#		
			#		self.selected_mechtype = neg_token.mechTypes[0]
			#		self.selected_authentication_context = self.authentication_contexts[neg_token.mechTypes[0]]
			#		#there is an option if onyl one auth type is set to have the auth token already in this message
			#		if neg_token.mechToken is not None:
			#			response, to_continue = await self.process_ctx_authenticate(neg_token.mechToken, flags = flags, seq_number = seq_number, is_rpc = is_rpc)
			#			if not response:
			#				return None, False
			#			response['supportedMech'] = MechType(self.selected_mechtype)	
			#			return NegTokenResp(response).dump(), to_continue
			#			
			#		else:
			#			response = {}
			#			response['negState'] = NegState('accept-incomplete')
			#			response['supportedMech'] = MechType(self.selected_mechtype)
			#			return NegTokenResp(response).dump(), True
				

				
			#elif isinstance(neg_token_raw, NegTokenResp):
			#	if selected_authentication_context is None:
			#		raise Exception('NegTokenResp got, but no authentication context selected!')
			#
			#	response, to_continue = await self.process_ctx_authenticate(neg_token.mechToken, flags = flags, seq_number = seq_number, is_rpc = is_rpc)
			#	return NegTokenResp(response.dump()), to_continue
				
		else:
			if self.selected_mechtype is None:
				if token is None:
					#first call to auth, we need to create NegTokenInit2
					#we must list all available auth types, if only one is present then generate initial auth data with it
					
					selected_name = None
					mechtypes = []
					for mechname in self.authentication_contexts:
						selected_name = mechname #only used if there is one!
						mechtypes.append(MechType(mechname))
					
					response = {}
					response['mechTypes'] = MechTypes(mechtypes)
					
					if len(mechtypes) == 1:
						self.selected_authentication_context = self.authentication_contexts[selected_name]
						self.selected_mechtype = selected_name
						result, to_continue = await self.selected_authentication_context.authenticate(None, is_rpc = is_rpc)
						if is_rpc == False:
							response['mechToken'] = result
						else:
							if not result:
								return None, False
							if str(response['mechTypes'][0]) == '1.2.840.48018.1.2.2':
								response['mechToken'] = KRB5Token(result).to_bytes()
								
								#response['mechToken'] = bytes.fromhex('2a864886f712010202') +  #???????
							else:
								raise Exception('NTLM as RPC GSSAPI not implemented!')
					
					### First message and ONLY the first message goes out with additional wrapping
					
					negtoken = NegotiationToken({'negTokenInit':NegTokenInit2(response)})
					
					
					#spnego = GSS_SPNEGO({'NegotiationToken':negtoken})
					return GSSAPI({'type': GSSType('1.3.6.1.5.5.2'), 'value':negtoken}).dump(), True
					
					
				else:
					#we have already send the NegTokenInit2, but it contained multiple auth types,
					#at this point server is replying which auth type to use
					neg_token_raw = NegotiationToken.load(token)
					neg_token = neg_token_raw.native
					
					if not isinstance(neg_token_raw, NegTokenResp):
						raise Exception('Server send init???')
						
					self.selected_authentication_context = self.authentication_contexts[neg_token.mechTypes[0]]
					self.selected_mechtype = neg_token['supportedMech']
	
					response, to_continue = await self.process_ctx_authenticate(neg_token['responseToken'], flags = flags, seq_number = seq_number, is_rpc = is_rpc)
					return NegTokenResp(response).dump(), to_continue
					
			else:
				#everything is netotiated, but authentication needs more setps
				neg_token_raw = NegotiationToken.load(token)
				neg_token = neg_token_raw.native
				response, to_continue = await self.process_ctx_authenticate(neg_token['responseToken'], flags = flags, seq_number = seq_number, is_rpc = is_rpc)
				if not response:
					return None, False
				return NegotiationToken({'negTokenResp':NegTokenResp(response)}).dump(), to_continue
	
def test():
	test_data = bytes.fromhex('a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000000000000000000000000a00d73a0000000f')
	neg_token = NegotiationToken.load(test_data)
	print(neg_token.native)


	test_data_2 = bytes.fromhex('a181ce3081cba0030a0101a10c060a2b06010401823702020aa281b50481b24e544c4d53535000020000000800080038000000158289e2a7314a557bdb11bf000000000000000072007200400000000a0063450000000f540045005300540002000800540045005300540001001200570049004e003200300031003900410044000400120074006500730074002e0063006f007200700003002600570049004e003200300031003900410044002e0074006500730074002e0063006f007200700007000800aec600bfc5fdd40100000000')
	neg_token = NegotiationToken.load(test_data_2)
	print(neg_token.native)

	test_data_3 = bytes.fromhex('a11b3019a0030a0100a3120410010000006b65125a00bb9ab400000000')
	neg_token = NegotiationToken.load(test_data_3)
	print(neg_token.native)

	mt = MechType('NTLMSSP - Microsoft NTLM Security Support Provider')
	print(mt)

	print(MechType.map('1.3.6.1.4.1.311.2.2.10'))
	print(MechType.unmap('1.3.6.1.4.1.311.2.2.10'))

	#spnego_test = SPNEGO()
	#spnego_test.authenticate(test_data_2)
if __name__ == '__main__':
	test()