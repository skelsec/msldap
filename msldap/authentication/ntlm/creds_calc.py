import io
import os
import hmac
import datetime

from msldap.crypto.symmetric import DES
from msldap.crypto.hashing import *
from msldap.authentication.ntlm.structures.challenge_response import *


class NTLMCredentials:
	@staticmethod
	def construct(ntlmNegotiate, ntlmChallenge, ntlmAuthenticate):
		# now the guessing-game begins

		if isinstance(ntlmAuthenticate.NTChallenge, NTLMv2Response):
		#if ntlmAuthenticate._use_NTLMv2:
			# this is a netNTLMv2 then, otherwise auth would have failed on protocol level
			creds = netntlmv2()
			creds.username = ntlmAuthenticate.UserName
			creds.domain   = ntlmAuthenticate.DomainName
			creds.ServerChallenge = ntlmChallenge.ServerChallenge
			creds.ClientResponse  = ntlmAuthenticate.NTChallenge.Response
			creds.ChallengeFromClinet = ntlmAuthenticate.NTChallenge.ChallengeFromClinet_hex

			creds2 = netlmv2()
			creds2.username = ntlmAuthenticate.UserName
			creds2.domain   = ntlmAuthenticate.DomainName
			creds2.ServerChallenge = ntlmChallenge.ServerChallenge
			creds2.ClientResponse  = ntlmAuthenticate.LMChallenge.Response
			creds2.ChallengeFromClinet = ntlmAuthenticate.LMChallenge.ChallengeFromClinet
			return [creds, creds2]

		else:
			if ntlmAuthenticate.NegotiateFlags & NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY:
				# extended security is used, this means that the LMresponse actually contains client challenge data
				# and the LM and NT respondses need to be combined to form the cred data
				creds = netntlm_ess()
				creds.username = ntlmAuthenticate.UserName
				creds.domain   = ntlmAuthenticate.DomainName
				creds.ServerChallenge = ntlmChallenge.ServerChallenge
				creds.ClientResponse  = ntlmAuthenticate.NTChallenge.Response
				creds.ChallengeFromClinet = ntlmAuthenticate.LMChallenge.Response

				return [creds]

			else:
				creds = netntlm()
				creds.username = ntlmAuthenticate.UserName
				creds.domain   = ntlmAuthenticate.DomainName
				creds.ServerChallenge = ntlmChallenge.ServerChallenge
				creds.ClientResponse  = ntlmAuthenticate.NTChallenge.Response
				
				if ntlmAuthenticate.NTChallenge.Response == ntlmAuthenticate.LMChallenge.Response:
					# the the two responses are the same, then the client did not send encrypted LM hashes, only NT
					return [creds]
					

				# CAME FOR COPPER, FOUND GOLD!!!!!
				# HOW OUTDATED IS YOUR CLIENT ANYHOW???
				creds2 = netlm()
				creds2.username = ntlmAuthenticate.UserName
				creds2.domain   = ntlmAuthenticate.DomainName
				creds2.ServerChallenge = ntlmChallenge.ServerChallenge
				creds2.ClientResponse  = ntlmAuthenticate.LMChallenge.Response
				return [creds2, creds]

class netlm:
	# not supported by hashcat?
	def __init__(self):
		# this part comes from the NTLMAuthenticate class
		self.username = None
		self.domain = None
		# this comes from the NTLMChallenge class
		self.ServerChallenge = None

		# this is from the LMv1Response class (that is a member of NTLMAuthenticate class)
		self.ClientResponse = None

	def to_credential(self):
		cred = Credential('netLM',
							username = self.username, 
							fullhash = '%s:$NETLM$%s$%s' % (self.username, self.ServerChallenge, self.ClientResponse)
						)
		return cred

	def verify(self, creds, credtype='plain'):
		"""
		Verifies the authentication data against the user credentials
		Be careful! If the credtype is 'hash' then LM hash is expected!
		:param creds: dictionary containing the domain, user, hash/password
		:param credtype: can be 'plain' or 'hash' this indicates what type of credential lookup to perform
		:return: bool
		"""

		# print('Creds: %s' % creds)
		if creds is None:
			return True

		if self.domain not in creds:
			return False
		if self.username not in creds[self.domain]:
			return False

		if credtype == 'plain':
			lm_hash = LMOWFv1(creds[self.domain][self.username])
		elif credtype == 'hash':
			lm_hash = bytes.fromhex(creds[self.domain][self.username])
		else:
			raise Exception('Unknown cred type!')

		calc_response = DESL(lm_hash, self.ServerChallenge)

		return self.ClientResponse == calc_response.hex()


class netlmv2:
	# not supported by hashcat?
	def __init__(self):
		# this part comes from the NTLMAuthenticate class
		self.username = None
		self.domain = None
		# this comes from the NTLMChallenge class
		self.ServerChallenge = None

		# this is from the LMv2Response class (that is a member of NTLMAuthenticate class)
		self.ClientResponse = None
		self.ChallengeFromClinet = None

	def to_credential(self):
		cred = Credential(
			'netLMv2',
			username = self.username,
			fullhash = '$NETLMv2$%s$%s$%s$%s' % (self.username, self.ServerChallenge, self.ClientResponse, self.ChallengeFromClinet)
		)
		return cred

	def verify(self, creds, credtype='plain'):
		"""
		Verifies the authentication data against the user credentials
		:param creds: dictionary containing the domain, user, hash/password
		:param credtype: can be 'plain' or 'hash' this indicates what type of credential lookup to perform
		:return: bool
		"""

		# print('Creds: %s' % creds)
		if creds is None:
			return True

		if self.domain not in creds:
			return False
		if self.username not in creds[self.domain]:
			return False

		if credtype == 'plain':
			lm_hash = LMOWFv2(creds[self.domain][self.username], self.username, self.domain)
		elif credtype == 'hash':
			lm_hash = LMOWFv2(None, self.username, self.domain, bytes.fromhex(creds[self.domain][self.username]))
		else:
			raise Exception('Unknown cred type!')

		hm = hmac_md5(lm_hash)
		hm.update(bytes.fromhex(self.ServerChallenge))
		hm.update(bytes.fromhex(self.ChallengeFromClinet))

		return self.ClientResponse == hm.hexdigest()


class netntlm_ess:
	def __init__(self):
		# this part comes from the NTLMAuthenticate class
		self.credentials = None
		# this comes from the NTLMChallenge class
		self.ServerChallenge = None

		self.LMResponse = None
		self.NTResponse = None
		
		self.SessionBaseKey = None
		
	
	# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d86303b5-b29e-4fb9-b119-77579c761370
	def calc_key_exchange_key(self):
		if not self.credentials.nt_hash:
			nt_hash = NTOWFv1(self.credentials.password)
		else:
			nt_hash = bytes.fromhex(self.credentials.nt_hash)
		
		hm = hmac_md5(self.SessionBaseKey)
		hm.update(self.ServerChallenge)
		hm.update(self.LMResponse.to_bytes()[:8])
				
		return hm.digest()
		
	@staticmethod
	def construct(server_challenge, client_challenge, credentials):
		ntlm_creds = netntlm_ess()
		ntlm_creds.credentials = credentials
		ntlm_creds.ServerChallenge = server_challenge
		
		if credentials.password:
			nt_hash = NTOWFv1(credentials.password)
			lm_hash = LMOWFv1(credentials.password)
		else:
			nt_hash = bytes.fromhex(credentials.nt_hash)
			lm_hash = bytes.fromhex(credentials.lm_hash) if credentials.lm_hash else None
		
		
		ntlm_creds.LMResponse = LMResponse()
		ntlm_creds.LMResponse.Response = client_challenge + b'\x00' * 16
		
		temp_1 = md5(server_challenge + client_challenge[:8]).digest()
		data = DESL(nt_hash, temp_1[:8])
		
		ntlm_creds.NTResponse = NTLMv1Response()
		ntlm_creds.NTResponse.Response = data
		
		ntlm_creds.SessionBaseKey = md4(nt_hash).digest()
		
		return ntlm_creds

	def to_credential(self):
		cred = Credential(
			'netNTLMv1-ESS',
			username = self.username,
			fullhash = '%s::%s:%s:%s:%s' % (self.credentials.username, self.credentials.domain, ntlm_creds.LMResponse.Response, ntlm_creds.NTResponse.Response, self.ServerChallenge)
		)
		return cred
		# u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c

	def calc_session_base_key(self, creds, credtype = 'plain'):
		if credtype == 'plain':
			nt_hash = NTOWFv1(creds[self.domain][self.username])
		elif credtype == 'hash':
			nt_hash = bytes.fromhex(creds[self.domain][self.username])
		else:
			raise Exception('Unknown cred type!')

		session_base_key = md4(nt_hash).digest()
		return session_base_key

	def verify(self, creds, credtype='plain'):
		"""
		Verifies the authentication data against the user credentials
		:param creds: dictionary containing the domain, user, hash/password
		:param credtype: can be 'plain' or 'hash' this indicates what type of credential lookup to perform
		:return: bool
		"""
		if creds is None:
			return True
		if self.domain not in creds:
			return False
		if self.username not in creds[self.domain]:
			return False

		if credtype == 'plain':
			nt_hash = NTOWFv1(creds[self.domain][self.username])
		elif credtype == 'hash':
			nt_hash = bytes.fromhex(creds[self.domain][self.username])
		else:
			raise Exception('Unknown cred type!')

		# print('Server chall: %s' % self.ServerChallenge)
		# print('Client chall: %s' % self.ChallengeFromClinet)

		temp_1 = md5(bytes.fromhex(self.ServerChallenge) + bytes.fromhex(self.ChallengeFromClinet)[:8]).digest()
		calc_response = DESL(nt_hash, temp_1[:8])
		# print('calc_response: %s' % calc_response.hex())
		# print('ClientResponse: %s' %  self.ClientResponse)

		return calc_response == bytes.fromhex(self.ClientResponse)


class netntlm:
	# not supported by hashcat?
	def __init__(self):
		# this part comes from the NTLMAuthenticate class
		self.credentials = None
		# this comes from the NTLMChallenge class
		self.ServerChallenge = None

		self.LMResponse = None
		self.NTResponse = None
		
		
		self.SessionBaseKey = None
		
	def calc_key_exchange_key(self, with_lm = False, non_nt_session_key = False):
	
		if self.credentials.password:
			lm_hash = LMOWFv1(self.credentials.password)
		else:
			lm_hash = self.credentials.lm_hash
		
		if with_lm:
			temp1 = DES(lm_hash[:7]).encrypt(self.LMResponse.to_bytes()[:8])
			temp2 = DES(lm_hash[7:8] + b'\xBD\xBD\xBD\xBD\xBD\xBD').encrypt(self.LMResponse.to_bytes()[:8])
			kex = temp1 + temp2

		else:
			if non_nt_session_key:
				kex = lm_hash[:8] + b'\x00' * 8
			else:
				kex = self.SessionBaseKey
				
		return kex
		
	@staticmethod
	def construct(server_challenge, credentials):
		ntlm_creds = netntlm()
		ntlm_creds.credentials = credentials
		ntlm_creds.ServerChallenge = server_challenge
		
		if credentials.password:
			nt_hash = NTOWFv1(credentials.password)
			lm_hash = LMOWFv1(credentials.password)
		else:
			nt_hash = bytes.fromhex(credentials.nt_hash)
			lm_hash = bytes.fromhex(credentials.lm_hash) if credentials.lm_hash else None
		
		ntlm_creds.NTResponse = NTLMv1Response()
		ntlm_creds.NTResponse.Response = DESL(nt_hash, server_challenge)
		
		if lm_hash:
			ntlm_creds.LMResponse = LMResponse()
			ntlm_creds.LMResponse.Response = DESL(lm_hash, server_challenge)
		else:
			ntlm_creds.LMResponse = ntresponse
		
		ntlm_creds.SessionBaseKey = md4(nt_hash).digest()
		
		return ntlm_creds

	def to_credential(self):
		cred = Credential('netNTLMv1',
							username = self.username, 
							fullhash = '%s:$NETNTLM$%s$%s' % (self.username, self.ServerChallenge, self.NTResponse.Response)
						)
		return cred
		#username:$NETNTLM$1122334455667788$B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233

	def calc_session_base_key(self, creds, credtype = 'plain'):
		if credtype == 'plain':
			nt_hash = NTOWFv1(creds[self.domain][self.username])
		elif credtype == 'hash':
			nt_hash = bytes.fromhex(creds[self.domain][self.username])
		else:
			raise Exception('Unknown cred type!')

		session_base_key = md4(nt_hash).digest()
		return session_base_key

	def verify(self, creds, credtype='plain'):
		"""
		Verifies the authentication data against the user credentials
		:param creds: dictionary containing the domain, user, hash/password
		:param credtype: can be 'plain' or 'hash' this indicates what type of credential lookup to perform
		:return: bool
		"""
		if creds is None:
			return True
		if self.domain not in creds:
			return False
		if self.username not in creds[self.domain]:
			return False

		if credtype == 'plain':
			nt_hash = NTOWFv1(creds[self.domain][self.username])
		elif credtype == 'hash':
			nt_hash = bytes.fromhex(creds[self.domain][self.username])
		else:
			raise Exception('Unknown cred type!')

		return DESL(nt_hash, self.ServerChallenge) == bytes.fromhex(self.ClientResponse)


class netntlmv2:
	def __init__(self):
		self.credentials = None
		
		# this comes from the NTLMChallenge class
		self.ServerChallenge = None

		# this is from the NTLMv2Response class (that is a member of NTLMAuthenticate class)
		#self.ClientResponse = None
		#self.ChallengeFromClinet = None
		
		self.LMResponse = None
		self.NTResponse = None
		
		
		self.SessionBaseKey = None
		
	# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d86303b5-b29e-4fb9-b119-77579c761370
	def calc_key_exchange_key(self):				
		return self.SessionBaseKey
		
	@staticmethod
	def construct(server_challenge, client_challenge, server_details, credentials, timestamp = None):
		ntlm_creds = netntlmv2()
		ntlm_creds.credentials = credentials
		ntlm_creds.ServerChallenge = server_challenge
		
		if not credentials.nt_hash and not credentials.password:
			raise Exception('Password or NT hash must be supplied!')
			
		if credentials.password:
			nt_hash_v2 = NTOWFv2(credentials.password, credentials.username, credentials.domain)
		else:
			nt_hash_v2 = NTOWFv2(None, credentials.username, credentials.domain, bytes.fromhex(credentials.nt_hash))
		
		if not timestamp:
			timestamp = datetime.datetime.utcnow()
		
		cc = NTLMv2ClientChallenge.construct(timestamp, client_challenge, server_details)
		temp = cc.to_bytes()
		
		hm = hmac_md5(nt_hash_v2)
		hm.update(server_challenge)
		hm.update(temp)
		
		NTProofStr = hm.digest()
		
		ntlm_creds.NTResponse = NTLMv2Response()
		ntlm_creds.NTResponse.Response = NTProofStr
		ntlm_creds.NTResponse.ChallengeFromClinet = cc
		
			
		hm = hmac_md5(nt_hash_v2)
		hm.update(server_challenge)
		hm.update(client_challenge)
		
		ntlm_creds.LMResponse = LMv2Response()
		ntlm_creds.LMResponse.Response = hm.digest()
		ntlm_creds.LMResponse.ChallengeFromClinet = client_challenge
		
		
		hm = hmac_md5(nt_hash_v2)
		hm.update(NTProofStr)
		ntlm_creds.SessionBaseKey = hm.digest()
		
		return ntlm_creds

	def to_credential(self):
		cred = Credential(
			'netNTLMv2',
			username = self.username,
			domain = self.domain,
			fullhash = '%s::%s:%s:%s:%s' % (self.credentials.username, self.credentials.domain, self.ServerChallenge, self.NTResponse.Response, self.NTResponse.ChallengeFromClinet)
		)
		return cred

	def verify(self, creds, credtype = 'plain'):
		"""
		Verifies the authentication data against the user credentials
		:param creds: dictionary containing the domain, user, hash/password
		:param credtype: can be 'plain' or 'hash' this indicates what type of credential lookup to perform 
		:return: bool
		"""

		# print('Creds: %s' % creds)
		if creds is None:
			return True

		if self.domain not in creds:
			return False
		if self.username not in creds[self.domain]:
			return False

		if credtype == 'plain':
			nt_hash = NTOWFv2(creds[self.domain][self.username], self.username, self.domain)
		elif credtype == 'hash':
			nt_hash = NTOWFv2(None, self.username, self.domain, bytes.fromhex(creds[self.domain][self.username]))
		else:
			raise Exception('Unknown cred type!')

		# print(self.ServerChallenge)
		# print(self.ChallengeFromClinet)

		hm = hmac_md5(nt_hash)
		hm.update(bytes.fromhex(self.ServerChallenge))
		hm.update(bytes.fromhex(self.ChallengeFromClinet))

		# print('M_nthash: %s' % nthash.hex())
		# print('M_temp: %s' % self.ChallengeFromClinet)
		# print('M_nthash: %s' % nthash.hex())
		# print('M_server_chall: %s' % self.ServerChallenge)
		# print('M_ntproof_string: %s' % self.ClientResponse)
		# print('M_ntproof_string_calc: %s' % hm.hexdigest())

		return self.ClientResponse == hm.hexdigest()


def LMOWFv1(password):
	LM_SECRET = b'KGS!@#$%'
	t1 = password[:14].ljust(14, '\x00').upper()
	d = DES(t1[:7].encode('ascii'))
	r1 = d.encrypt(LM_SECRET)
	d = DES(t1[7:].encode('ascii'))
	r2 = d.encrypt(LM_SECRET)

	return r1+r2
	

def NTOWFv1(password):
	return md4(password.encode('utf-16le')).digest()


def LMOWFv2(Passwd, User, UserDom, PasswdHash = None):
	return NTOWFv2(Passwd, User, UserDom, PasswdHash)


def NTOWFv2(Passwd, User, UserDom, PasswdHash = None):
	if PasswdHash is not None:
		fp = hmac_md5(PasswdHash)
	else:
		fp = hmac_md5(NTOWFv1(Passwd))
	fp.update((User.upper() + UserDom).encode('utf-16le'))
	return fp.digest()


def DESL(K, D):
	"""
	Indicates the encryption of an 8-byte data item D with the 16-byte key K
	using the Data Encryption Standard Long (DESL) algorithm.
	The result is 24 bytes in length.
	:param K:
	:param D:
	:return:
	"""
	if len(K) != 16:
		raise Exception("K MUST be 16 bytes long")
	if len(D) != 8:
		raise Exception("D MUST be 8 bytes long")

	res = b''
	res += DES(K[:7]).encrypt(D)
	res += DES(K[7:14]).encrypt(D)
	res += DES(K[14:] + b'\x00'*5).encrypt(D)
	return res
