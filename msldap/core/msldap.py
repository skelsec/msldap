import logging
from ldap3 import Server, Connection, ALL
import getpass

from msldap.ldap_objects.adinfo import MSADInfo
from msldap.ldap_objects.aduser import MSADUser

class UserCredential:
	def __init__(self, domain=None, username= None, password = None):
		self.domain   = domain
		self.username = username
		self.password = password

		if username.find('\\') != -1:
			self.domain, self.username = username.split('\\')

		if not self.domain:
			raise Exception('Domain needs to be set, either via the "domain" parameter or by supplying the full username in "DOMAIN\\\\Username format"')

	def get_msuser(self):
		return '%s\\%s' % (self.domain,self.username)

	def get_password(self):
		if self.password is None:
			self.password = getpass.getpass('Enter password: ')

		return self.password

class TargetServer:
	def __init__(self, tree, host, port = 389, proto = 'ldap'):
		self.proto = proto
		self.host = host
		self.tree = tree
		self.port = port

	def get_host(self):
		return '%s://%s:%s' % (self.proto, self.host, self.port)

	def is_ssl(self):
		return self.proto.lower() == 'ldaps'

class MSLDAP:
	def __init__(self, login_credential, target_server, ldap_query_page_size = 1000):
		self.login_credential = login_credential
		self.target_server = target_server

		self.ldap_query_page_size = ldap_query_page_size #default for MSAD
		self._ldapinfo = None
		self._srv = None
		self._con = None

	def get_server_info(self, anonymous = True):
		"""
		Performs bind on the server and grabs the DSA info object.
		If anonymous is set to true, then it will perform anonymous bind, not using user credentials
		Otherwise it will use the credentials set in the object constructor.
		"""
		if anonymous == True:
			logging.debug('Getting server info via Anonymous BIND on server %s' % self.target_server)
			server = Server(self.target_server.get_host(), use_ssl=self.target_server.is_ssl(), get_info=ALL)
			conn = Connection(server, auto_bind=True)
			logging.debug('Got server info')
		else:
			logging.debug('Getting server info via credentials supplied on server %s' % self.target_server)
			self._srv = Server(self.target_server.get_host(), use_ssl=self.target_server.is_ssl(), get_info=ALL)
			self._con = Connection(self._srv, self.login_credential.get_msuser(), self.login_credential.get_password())
			logging.debug('Performing BIND to server %s' % self.target_server.get_host())
			if not self._con.bind():
				if 'description' in self._con.result:
					raise Exception('Failed to bind to server! Reason: %s' % self._con.result['description'])
				raise Exception('Failed to bind to server! Reason: %s' % self._con.result)
			logging.debug('Connected to server!')
		return server.info
		

	def connect(self, anonymous = False):
		logging.debug('Connecting to server %s' % self.target_server)
		if anonymous == False:
			self._srv = Server(self.target_server.get_host(), use_ssl=self.target_server.is_ssl(), get_info=ALL)
			self._con = Connection(self._srv, self.login_credential.get_msuser(), self.login_credential.get_password())
			logging.debug('Performing BIND to server %s' % self.target_server.get_host())
			if not self._con.bind():
				if 'description' in self._con.result:
					raise Exception('Failed to bind to server! Reason: %s' % self._con.result['description'])
				raise Exception('Failed to bind to server! Reason: %s' % self._con.result)
			logging.debug('Connected to server!')
		else:
			self._srv = Server(self.target_server.get_host(), use_ssl=self.target_server.is_ssl(), get_info=ALL)
			self._con = Connection(self._srv)
			logging.debug('Performing ANONYMOUS BIND to server %s' % self.target_server.get_host())
			if not self._con.bind():
				if 'description' in self._con.result:
					raise Exception('Failed to bind to server! Reason: %s' % self._con.result['description'])
				raise Exception('Failed to bind to server! Reason: %s' % self._con.result)
			logging.debug('Connected to server!')

	def pagedsearch(self, ldap_filter, attributes):
		"""
		Performs a paged search on the AD, using the filter and attributes as a normal query does.
		Needs to connect to the server first!
		ldap_filter: str : LDAP query filter
		attributes: list : Attributes list to recieve in the result
		"""
		logging.debug('Paged search, filter: %s attributes: %s' % (ldap_filter, ','.join(attributes)))
		ctr = 0
		entries = self._con.extend.standard.paged_search(self.target_server.tree, ldap_filter, attributes = attributes, paged_size = self.ldap_query_page_size)
		for entry in entries:
			if 'raw_attributes' in entry and 'attributes' in entry:
				# TODO: return ldapuser object
				ctr += 1
				if ctr % self.ldap_query_page_size == 0:
					logging.info('New page requested. Result count: %d' % ctr)
				yield entry



	def get_all_user_objects(self):
		"""
		Fetches all user objects from the AD, and returns MSADUser object
		"""
		logging.debug('Polling AD for all user objects')
		ldap_filter = r'(objectClass=user)'

		attributes = MSADUser.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			# TODO: return ldapuser object
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logging.debug('Finished polling for entries!')

	def get_user(self, sAMAccountName):
		"""
		Fetches one user object from the AD, based on the sAMAccountName attribute (read: username) 
		"""
		logging.debug('Polling AD for user %s'% sAMAccountName)
		ldap_filter = r'(&(objectClass=user)(sAMAccountName=%s)' % sAMAccountName
		attributes = MSADUser.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			# TODO: return ldapuser object
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logging.debug('Finished polling for entries!')

	def get_ad_info(self):
		"""
		Polls for basic AD information (needed for determine password usage characteristics!)
		"""
		logging.debug('Polling AD for basic info')
		ldap_filter = r'(distinguishedName=%s)' % self.target_server.tree
		attributes = MSADInfo.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			self._ldapinfo = MSADInfo.from_ldap(entry)
			return self._ldapinfo

		logging.debug('Poll finished!')

	def get_all_service_user_objects(self, include_machine = False):
		"""
		Fetches all service user objects from the AD, and returns MSADUser object.
		Service user refers to an user whith SPN (servicePrincipalName) attribute set
		"""
		logging.debug('Polling AD for all user objects, machine accounts included: %s'% include_machine)
		if include_machine == True:
			ldap_filter = r'(servicePrincipalName=*)'
		else:
			ldap_filter = r'(&(servicePrincipalName=*)(!(sAMAccountName = *$)))'

		attributes = MSADUser.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			# TODO: return ldapuser object
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logging.debug('Finished polling for entries!')

