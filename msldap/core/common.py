
import getpass
import enum
from urllib.parse import urlparse
import hashlib
import ipaddress


from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, BASE, ALL_ATTRIBUTES


class MSLDAPSecretType(enum.Enum):
	NT = 'NT'
	SSPI = 'SSPI'
	PASSWORD = 'PASSWORD'
	ANONYMOUS = 'ANONYMOUS'

class MSLDAPCredential:
	def __init__(self, domain=None, username= None, secret_type = None, secret = None):
		self.domain   = domain
		self.username = username
		self.secret_type = secret_type
		self.secret = secret
		
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
		if self.secret_type in [MSLDAPSecretType.NT, MSLDAPSecretType.SSPI]:
			return NTLM
		return SIMPLE
	
	@staticmethod
	def get_dummy_sspi():
		return MSLDAPCredential(domain='TEST', username= 'TEST', secret_type = MSLDAPSecretType.SSPI, secret = None)

	def get_password(self):
		if self.secret_type == MSLDAPSecretType.SSPI:
			#this is here because of ldap3 module requires a password set 
			return 'test'
		elif self.secret_type == MSLDAPSecretType.NT:
			if len(self.secret) == 32:
				try:
					bytes.fromhex(self.secret)
				except:
					#this is a plaintext password!
					a = hashlib.new('md4')
					a.update(self.secret.encode('utf-16-le'))
					hs = a.hexdigest()
					return '%s:%s' % (hs, hs)
				else:
					return '%s:%s' % (self.secret, self.secret)
			else:
				#this is a plaintext password!
				a = hashlib.new('md4')
				a.update(self.secret.encode('utf-16-le'))
				hs = a.hexdigest()
				return '%s:%s' % (hs, hs)
		else:
			return self.secret
		
	def is_anonymous(self):
		return self.secret_type == MSLDAPSecretType.ANONYMOUS
		
	@staticmethod
	def from_connection_string(s):
		"""
		Credential input format:
		<domain>/<username>/<secret_type>:<secret>@<dc_ip_or_hostname_or_ldap_url>
		"""
		cred = MSLDAPCredential()
		
		cred.domain, t = s.split('/', 1)
		cred.username, t = t.split('/', 1)
		secret_type, t = t.split(':', 1)
		secret, target = t.rsplit('@', 1)
		
		if secret_type.upper() in ['PW','PASS', 'PASSWORD']:
			secret_type = 'PASSWORD'
		
		try:
			cred.secret_type = MSLDAPSecretType(secret_type.upper())
		except Exception as e:
			raise Exception('%s is not a valid secret type! values accepted: pw/pass/password/sspi/nt')
			
		if cred.secret_type == MSLDAPSecretType.PASSWORD and secret == '':
			secret = getpass.getpass('Please enter LDAP password:')
		
		cred.secret = secret
		
		return cred


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

class MSLDAPTargetProxySecretType(enum.Enum):
	NONE = 'NONE'

class MSLDAPTargetProxyServerType(enum.Enum):
	SOCKS5 = 'SOCKS5'

class MSLDAPTargetProxy:
	def __init__(self):
		self.ip = None
		self.port = 1080
		self.timeout = 10
		self.proxy_type = None
		self.username = None
		self.domain = None
		self.secret = None
		self.secret_type = None #SMBCredentialsSecretType
		
	def to_target_string(self):
		pass
	
	@staticmethod
	def from_connection_string(s):
		"""
		protocol/domain/user/secret-type:secret@proxy_server:port
		"""
		port = 1080
		t, target = s.rsplit('@', 1)
		ip = target
		if target.find(':') != -1:
			ip, port = target.split(':')
			
		st = MSLDAPTargetProxy()
		st.port = int(port)
		st.ip = ip

		t, secret = t.split(':', 1)
		elems = t.split('/')
		st.proxy_type = MSLDAPTargetProxyServerType(elems[0].upper())
		st.domain = elems[1]
		st.user = elems[2]
		st.secret_type = MSLDAPTargetProxySecretType(elems[3].upper())
		st.secret = secret
	
		return st
		
	def __str__(self):
		t = '==== MSLDAPTargetProxy ====\r\n'
		for k in self.__dict__:
			print(k)
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
		
		
if __name__ == '__main__':
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
	
	