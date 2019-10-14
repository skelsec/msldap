
import getpass
import enum
from urllib.parse import urlparse, parse_qs
import hashlib
import ipaddress


from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, BASE, ALL_ATTRIBUTES

#class MSLDAPSecretType(enum.Enum):
#	NT = 'NT'
#	SSPI = 'SSPI'
#	PASSWORD = 'PASSWORD'
#	ANONYMOUS = 'ANONYMOUS'
#	MULTIPLEXOR = 'MULTIPLEXOR'
#	MULTIPLEXOR_SSL = 'MULTIPLEXOR_SSL'

#class MSLDAPTargetProxySecretType(enum.Enum):
#	NONE = 'NONE'
#	PLAIN = 'PLAIN'

class LDAPProtocol(enum.Enum):
	LDAP = 'LDAP'
	LDAPS = 'LDAPS'

class LDAPAuthProtocol(enum.Enum):
	ANONYMOUS = 'ANONYMOUS'
	PLAIN = 'PLAIN'
	NTLM = 'NTLM'
	SSPI = 'SSPI'
	MULTIPLEXOR = 'MULTIPLEXOR'
	MULTIPLEXOR_SSL = 'MULTIPLEXOR_SSL'

class LDAPProxyType(enum.Enum):
	SOCKS5 = 'SOCKS5'
	SOCKS5_SSL = 'SOCKS5_SSL'
	MULTIPLEXOR = 'MULTIPLEXOR'
	MULTIPLEXOR_SSL = 'MULTIPLEXOR_SSL'

class MSLDAPURLDecoder:
	def __init__(self, url):
		self.url = url
		self.ldap_scheme = None
		self.auth_scheme = None
		self.proxy_scheme = None

		self.domain = None
		self.username = None
		self.password = None
		self.auth_settings = {}

		self.ldap_proto = None
		self.ldap_host = None
		self.ldap_port = None

		self.proxy_domain = None
		self.proxy_username = None
		self.proxy_password = None
		self.proxy_scheme = None
		self.proxy_ip = None
		self.proxy_port = None
		self.proxy_settings = {}

		self.parse()


	def get_credential(self):
		return MSLDAPCredential(domain=self.domain, username=self.username, password = self.password, auth_method=self.auth_scheme, settings = self.auth_settings)

	def get_target(self):
		target = MSLDAPTarget(self.ldap_host, port = self.ldap_port, proto = self.ldap_proto.lower())
		if self.proxy_scheme is not None:
			proxy = MSLDAPTargetProxy()
			proxy.ip = self.proxy_ip
			proxy.port = self.proxy_port
			proxy.timeout = 10
			proxy.proxy_type = self.proxy_scheme
			proxy.username = self.proxy_username
			proxy.domain = self.proxy_domain
			proxy.settings = self.proxy_settings

			target.proxy = proxy
		return target

	def scheme_decoder(self, scheme):
		schemes = scheme.upper().split('+')
		self.ldap_scheme = LDAPProtocol(schemes[0])
		self.ldap_proto = self.ldap_scheme.value.lower()

		if len(schemes) == 1:
			return
		
		try:
			self.auth_scheme = LDAPAuthProtocol(schemes[1])
		except:
			raise Exception('Uknown scheme!')
		
		return

	def parse(self):
		url_e = urlparse(self.url)
		self.scheme_decoder(url_e.scheme)

		
		if url_e.username is not None:
			if url_e.username.find('\\') != -1:
				self.domain , self.username = url_e.username.split('\\')
			else:
				self.domain = None
				self.username = url_e.username

			if self.auth_scheme is None:
				self.auth_scheme = LDAPAuthProtocol.PLAIN

		self.password = url_e.password			

		if self.auth_scheme == LDAPAuthProtocol.SSPI:
			if self.username is None:
				self.username = '<CURRENT>'
			if self.password is None:
				self.password = '<CURRENT>'
			if self.domain is None:
				self.domain = '<CURRENT>'

		if self.auth_scheme == LDAPAuthProtocol.NTLM:
			if len(self.password) == 32:
				try:
					bytes.fromhex(self.password)
				except:
					a = hashlib.new('md4')
					a.update(self.password.encode('utf-16-le'))
					hs = a.hexdigest()
					self.password = '%s:%s' % (hs, hs)
				else:
					self.password = '%s:%s' % (self.password, self.password)
			else:
				a = hashlib.new('md4')
				a.update(self.password.encode('utf-16-le'))
				hs = a.hexdigest()
				self.password = '%s:%s' % (hs, hs)
		self.ldap_host = url_e.hostname
		if url_e.port is not None:
			self.ldap_port = int(url_e.port)
		else:
			if self.ldap_scheme == LDAPProtocol.LDAP:
				self.ldap_port = 389
			else:
				self.ldap_port = 636

		#now for the url parameters
		"""
		ldaps://user:pass@10.10.10.2/?proxyhost=127.0.0.1&proxyport=8888&proxyuser=dddd&proxypass=ssss&dns=127.0.0.1
		"""
		if url_e.query is not None:
			query = parse_qs(url_e.query)
			for k in query:
				if k == 'dns':
					self.dns = query[k] #multiple dns can be set, so not trimming here
				elif k.startswith('auth'):
					self.auth_settings[k[len('auth'):]] = query[k] #the result is a list for each entry because this preprocessor is not aware which elements should be lists!

				elif k.startswith('proxy'):
					if k == 'proxytype':
						self.proxy_scheme = LDAPProxyType(query[k][0].upper())
					elif k == 'proxyhost':
						self.proxy_ip = query[k][0]
					elif k == 'proxyuser':
						if query[k][0].find('\\') != -1:
							self.proxy_domain, self.proxy_username = query[k][0].split('\\')
						else:
							self.proxy_username = query[k][0]
					elif k == 'proxypass':
						self.proxy_password = query[k][0]
					elif k == 'proxyport':
						self.proxy_port = int(query[k][0])
					else:
						self.proxy_settings[k[len('proxy'):]] = query[k] #the result is a list for each entry because this preprocessor is not aware which elements should be lists!

				#####TODOOOO FIX THIS!!!!
				elif k.startswith('same'):
					self.auth_settings[k[len('same'):]] = query[k]
					if k == 'sametype':
						self.proxy_scheme = LDAPProxyType(query[k][0].upper())
					elif k == 'samehost':
						self.proxy_ip = query[k][0]
					elif k == 'sameuser':
						if query[k][0].find('\\') != -1:
							self.proxy_domain, self.proxy_username = query[k][0].split('\\')
						else:
							self.proxy_username = query[k][0]
					elif k == 'samepass':
						self.proxy_password = query[k][0]
					elif k == 'sameport':
						self.proxy_port = int(query[k][0])
					else:
						self.proxy_settings[k[len('same'):]] = query[k] #the result is a list for each entry because this preprocessor is not aware which elements should be lists!
		
		#setting default proxy ports
		if self.proxy_scheme in [LDAPProxyType.SOCKS5, LDAPProxyType.SOCKS5_SSL]:
			if self.proxy_port is None:
				self.proxy_port = 1080
		
		if self.proxy_scheme in [LDAPProxyType.MULTIPLEXOR, LDAPProxyType.MULTIPLEXOR_SSL]:
			if self.proxy_port is None:
				self.proxy_port = 9999

		#sanity checks...
		if self.proxy_scheme is not None:
			if self.proxy_ip is None:
				raise Exception('proxyserver MUST be provided if using proxy')
		
		if self.proxy_scheme in [LDAPProxyType.MULTIPLEXOR, LDAPProxyType.MULTIPLEXOR_SSL]:
			if 'agentid' not in self.proxy_settings:
				raise Exception('multiplexor proxy reuires agentid to be set! Set it via proxyagentid parameter!')

		if self.auth_scheme in [LDAPAuthProtocol.PLAIN, LDAPAuthProtocol.NTLM, LDAPAuthProtocol.SSPI]:
			if self.username is None:
				raise Exception('For authentication protocol %s the username MUST be specified!' % self.auth_scheme.value)
			if self.password is None:
				raise Exception('For authentication protocol %s the password MUST be specified!' % self.auth_scheme.value)
		
		if self.auth_scheme is None:
			if self.username is None and self.password is None:
				self.auth_scheme = LDAPAuthProtocol.ANONYMOUS
			else:
				raise Exception('Could not parse authentication protocol!')
				



class MSLDAPCredential:
	def __init__(self, domain=None, username= None, password = None, auth_method = None, settings = None):
		self.auth_method = auth_method
		self.domain   = domain
		self.username = username
		self.password = password
		self.settings = settings

	"""
	'ldap://domain\test@10.10.10.2',
		'ldap://domain\test:password@10.10.10.2:9999',
		'ldaps://10.10.10.2',
		'ldaps://10.10.10.2:9999',
		'ldaps://test:password@10.10.10.2',
		'ldaps://domain\test@10.10.10.2',
		'ldaps://domain\test:password@10.10.10.2:9999',
		'ldaps+socks5://proxy_user:proxy_password@127.0.0.1/?target=10.10.10.2&port=9999&user=test&domain=DOMAIN&password=aaa',
		'ldaps+socks5://proxy_user:proxy_password@127.0.0.1:9423/?target=10.10.10.2&user=test&domain=DOMAIN&password=aaa',
		'ldaps+multiplexor://proxy_user:proxy_password@127.0.0.1:9423/agentid/?target=10.10.10.2&user=test&domain=DOMAIN&password=aaa',
	"""
		
	help_epilog = """==== Extra Help ====
ldap_connection_string secret types: 
   - Plaintext: "pw" or "pass" or "password"
   - NT hash: "nt"
   - SSPI: "sspi" 
   
   Example:
   - Plaintext:
      TEST/user/pw:@192.168.1.1 (you will be propted for password)
      TEST/user/pw:SecretPassword@192.168.1.1
      TEST/user/password:SecretPassword@192.168.1.1
      TEST/user/pass:SecretPassword@192.168.1.1
   - NT hash:
      TEST/user/nt:921a7fece11f4d8c72432e41e40d0372@192.168.1.1
   - SSPI:
      TEST/user/sspi:@192.168.1.1

"""

	def get_msuser(self):
		if not self.domain:
			return self.username

		return '%s\\%s' % (self.domain,self.username)

	def get_authmethod(self):
		if self.auth_method in [LDAPAuthProtocol.NTLM, LDAPAuthProtocol.SSPI, LDAPAuthProtocol.MULTIPLEXOR, LDAPAuthProtocol.MULTIPLEXOR_SSL]:
			return NTLM
		return SIMPLE
	
	#@staticmethod
	#def get_dummy_sspi():
	#	return MSLDAPCredential(domain='TEST', username= 'TEST', secret_type = MSLDAPSecretType.SSPI, secret = None)

	#def get_password(self):
	#	if self.secret_type == MSLDAPSecretType.SSPI:
	#		#this is here because of ldap3 module requires a password set 
	#		return 'test'
	#	elif self.secret_type == MSLDAPSecretType.NT:
	#		if len(self.secret) == 32:
	#			try:
	#				bytes.fromhex(self.secret)
	#			except:
	#				#this is a plaintext password!
	#				a = hashlib.new('md4')
	#				a.update(self.secret.encode('utf-16-le'))
	#				hs = a.hexdigest()
	#				return '%s:%s' % (hs, hs)
	#			else:
	#				return '%s:%s' % (self.secret, self.secret)
	#		else:
	#			#this is a plaintext password!
	#			a = hashlib.new('md4')
	#			a.update(self.secret.encode('utf-16-le'))
	#			hs = a.hexdigest()
	#			return '%s:%s' % (hs, hs)
	#	else:
	#		return self.secret
		
	def is_anonymous(self):
		return self.auth_method == LDAPAuthProtocol.ANONYMOUS
		
	#@staticmethod
	#def from_connection_string(s):
	#	"""
	#	Credential input format:
	#	<domain>/<username>/<secret_type>:<secret>@<dc_ip_or_hostname_or_ldap_url>
	#	"""
	#	cred = MSLDAPCredential()
	#	
	#	cred.domain, t = s.split('/', 1)
	#	cred.username, t = t.split('/', 1)
	#	secret_type, t = t.split(':', 1)
	#	secret, target = t.rsplit('@', 1)
	#	
	#	if secret_type.upper() in ['PW','PASS', 'PASSWORD']:
	#		secret_type = 'PASSWORD'
	#	
	#	try:
	#		cred.secret_type = MSLDAPSecretType(secret_type.upper())
	#	except Exception as e:
	#		raise Exception('%s is not a valid secret type! values accepted: pw/pass/password/sspi/nt')
	#		
	#	if cred.secret_type == MSLDAPSecretType.PASSWORD and secret == '':
	#		secret = getpass.getpass('Please enter LDAP password:')
	#	
	#	cred.secret = secret
	#	
	#	return cred

	def __str__(self):
		t = '==== MSLDAPCredential ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t


class MSLDAPTarget:
	def __init__(self, host, port = 389, proto = 'ldap', tree = None, proxy = None):
		self.proto = proto
		self.host = host
		self.tree = tree
		self.port = port
		self.proxy = proxy

	def get_host(self):
		return '%s://%s:%s' % (self.proto, self.host, self.port)

	def is_ssl(self):
		return self.proto.lower() == 'ldaps'
		
		
	@staticmethod
	def from_connection_string(s):
		"""
		Credential input format:
		<domain>/<username>/<secret_type>:<secret>@<dc_ip_or_hostname_or_ldap_url>
		"""
		
		t, conn = s.rsplit('@', 1)
		if conn.find('://') != -1:
			o = urlparse(conn)
			if o.netloc.find(':') != -1:
				host, port = o.netloc.split(':')
			else:
				host = o.netloc
				port = 389
			return MSLDAPTarget(host, port = port, proto = o.scheme)
		else:
			if conn.find(':') != -1:
				host, port = conn.split(':')
			else:
				host = conn
				port = 389
			
			return MSLDAPTarget(host, port = port)
	
	def __str__(self):
		t = '==== MSLDAPTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t

class MSLDAPTargetProxy:
	def __init__(self):
		self.ip = None
		self.port = 1080
		self.timeout = 10
		self.proxy_type = None
		self.username = None
		self.domain = None
		self.secret = None
		self.secret_type = None
		self.settings = {}
		
	def __str__(self):
		t = '==== MSLDAPTargetProxy ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
		
		
if __name__ == '__main__':
	url_tests = [
		'ldap://10.10.10.2',
		'ldap://10.10.10.2:9999',
		'ldap://test:password@10.10.10.2',
		'ldap://domain\\test@10.10.10.2', #this must fail!
		'ldap://domain\\test:password@10.10.10.2:9999',
		'ldaps+sspi://10.10.10.2',
		'ldaps://10.10.10.2:9999',
		'ldaps://test:password@10.10.10.2',
		'ldaps://domain\\test@10.10.10.2',
		'ldaps://domain\\test:password@10.10.10.2:9999',
		'ldaps://DOMAIN\\test:password@10.10.10.2:9999/?proxytype=socks5&proxyserver=127.0.0.1',
		'ldaps://DOMAIN\\test:password@10.10.10.2:9999/?proxytype=socks5&proxyserver=127.0.0.1&proxyuser=admin&proxypass=alma',
		'ldaps://DOMAIN\\test:password@10.10.10.2:9999/?proxytype=multiplexor&proxyserver=127.0.0.1&proxyport=9999&proxyuser=admin&proxypass=alma',
		'ldaps://10.10.10.2',
		'ldaps://10.10.10.2:6666',
		'ldaps+ntlm://DOMAIN\\test:password@10.10.10.2/?proxytype=socks5&proxyserver=127.0.0.1',
		'ldaps+sspi://domain\\test:password@10.10.10.2:9999',
		'ldaps+sspi://10.10.10.2:9999',
		'ldaps+sspi://domain\\test@10.10.10.2:9999',
		'ldap+multiplexor://10.10.10.2/?proxytype=multiplexor&proxyserver=127.0.0.1&proxyport=9999&proxyagentid=477532db-348c-4d3e-9a4d-4f86d38986dc&authip=127.0.0.1&authport=9999&authagentid=477532db-348c-4d3e-9a4d-4f86d38986dc'

	]
	for url in url_tests:
		print('===========================================================================')
		print(url)
		try:
			dec = MSLDAPURLDecoder(url)
			creds = dec.get_credential()
			target = dec.get_target()
		except Exception as e:
			import traceback
			traceback.print_exc()
			print('ERROR! Reason: %s' % e)
			input()
		else:
			print(str(creds))
			print(str(target))
			input()



	"""
	test1 = 'TEST.corp/victim/pw:TESTPasswo@@@rd:!@ldaps://127.0.0.1:5544'
	
	cred = MSLDAPCredential.from_connection_string(test1)
	
	assert cred.domain == 'TEST.corp'
	assert cred.username == 'victim'
	assert cred.secret_type == MSLDAPSecretType.PASSWORD
	assert cred.secret == 'TESTPasswo@@@rd:!'
	
	conn = MSLDAPTarget.from_connection_string(test1)
	assert conn.get_host() == 'ldaps://127.0.0.1:5544'
	
	test2 = 'TEST.corp/victim/sspi:@127.0.0.1:5544'
	cred = MSLDAPCredential.from_connection_string(test2)

	assert cred.domain == 'TEST.corp'
	assert cred.username == 'victim'
	assert cred.secret_type == MSLDAPSecretType.SSPI
	assert cred.secret == ''
	conn = MSLDAPTarget.from_connection_string(test2)
	assert conn.get_host() == 'ldap://127.0.0.1:5544'
	
	test3 = 'TEST.corp/victim/pass:@127.0.0.1:5544'
	cred = MSLDAPCredential.from_connection_string(test3)
	"""
	
	