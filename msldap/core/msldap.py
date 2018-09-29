#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import getpass
from msldap import logger
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE


from ..ldap_objects import *

class MSLDAPUserCredential:
	def __init__(self, domain=None, username= None, password = None, is_ntlm = False):
		self.domain   = domain
		self.username = username
		self.password = password
		self.is_ntlm = is_ntlm

		if username.find('\\') != -1:
			self.domain, self.username = username.split('\\')

		if not self.domain:
			raise Exception('Domain needs to be set, either via the "domain" parameter or by supplying the full username in "DOMAIN\\\\Username format"')

	def get_msuser(self):
		return '%s\\%s' % (self.domain,self.username)

	def get_authmethod(self):
		if self.is_ntlm:
			return NTLM
		return SIMPLE

	def get_password(self):
		if self.is_ntlm == True:
			# Are we passing the hash... maybe?
			
			if self.password and len(self.password) == 32:
				try:
					bytes.fromhex(self.password)
				except Exception as e:
					# this is not a hex password just happens to be 32 chars long
					return self.password
				else:
					#we think that user is trying to pass the hash
					#problem, is that ldap3 module only accepts the "LM:NT" format, where both hash types are filled
					#so we do a slight conversion
					return '%s:%s' % ('a'*32, self.password)
		if self.password is None:
			self.password = getpass.getpass('Enter password: ')

		return self.password

class MSLDAPTargetServer:
	def __init__(self, host, port = 389, proto = 'ldap', tree = None):
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
		self._tree = self.target_server.tree
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
			logger.debug('Getting server info via Anonymous BIND on server %s' % self.target_server.get_host())
			server = Server(self.target_server.get_host(), use_ssl=self.target_server.is_ssl(), get_info=ALL)
			conn = Connection(server, auto_bind=True)
			logger.debug('Got server info')
		else:
			logger.debug('Getting server info via credentials supplied on server %s' % self.target_server.get_host())
			server = Server(self.target_server.get_host(), use_ssl=self.target_server.is_ssl(), get_info=ALL)
			conn = Connection(self._srv, user=self.login_credential.get_msuser(), password=self.login_credential.get_password(), authentication=self.login_credential.get_authmethod())
			logger.debug('Performing BIND to server %s' % self.target_server.get_host())
			if not self._con.bind():
				if 'description' in self._con.result:
					raise Exception('Failed to bind to server! Reason: %s' % conn.result['description'])
				raise Exception('Failed to bind to server! Reason: %s' % conn.result)
			logger.debug('Connected to server!')
		return server.info
		

	def connect(self, anonymous = False):
		logger.debug('Connecting to server %s' % self.target_server.get_host())
		if anonymous == False:
			self._srv = Server(self.target_server.get_host(), use_ssl=self.target_server.is_ssl(), get_info=ALL)
			self._con = Connection(self._srv, user=self.login_credential.get_msuser(), password=self.login_credential.get_password(), authentication=self.login_credential.get_authmethod())
			logger.debug('Performing BIND to server %s' % self.target_server.get_host())
			if not self._con.bind():
				if 'description' in self._con.result:
					raise Exception('Failed to bind to server! Reason: %s' % self._con.result['description'])
				raise Exception('Failed to bind to server! Reason: %s' % self._con.result)
			logger.debug('Connected to server!')
		else:
			self._srv = Server(self.target_server.get_host(), use_ssl=self.target_server.is_ssl(), get_info=ALL)
			self._con = Connection(self._srv)
			logger.debug('Performing ANONYMOUS BIND to server %s' % self.target_server.get_host())
			if not self._con.bind():
				if 'description' in self._con.result:
					raise Exception('Failed to bind to server! Reason: %s' % self._con.result['description'])
				raise Exception('Failed to bind to server! Reason: %s' % self._con.result)
			logger.debug('Connected to server!')

		if not self._tree:
			logger.debug('Search tree base not defined, selecting root tree')
			info = self.get_server_info()
			self._tree = info.other['rootDomainNamingContext'][0]
			logger.debug('Selected tree: %s' % self._tree)

	def pagedsearch(self, ldap_filter, attributes):
		"""
		Performs a paged search on the AD, using the filter and attributes as a normal query does.
		Needs to connect to the server first!
		ldap_filter: str : LDAP query filter
		attributes: list : Attributes list to recieve in the result
		"""
		logger.debug('Paged search, filter: %s attributes: %s' % (ldap_filter, ','.join(attributes)))
		ctr = 0
		entries = self._con.extend.standard.paged_search(self._tree, ldap_filter, attributes = attributes, paged_size = self.ldap_query_page_size)
		for entry in entries:
			if 'raw_attributes' in entry and 'attributes' in entry:
				# TODO: return ldapuser object
				ctr += 1
				if ctr % self.ldap_query_page_size == 0:
					logger.info('New page requested. Result count: %d' % ctr)
				yield entry



	def get_all_user_objects(self):
		"""
		Fetches all user objects from the AD, and returns MSADUser object
		"""
		logger.debug('Polling AD for all user objects')
		ldap_filter = r'(objectClass=user)'

		attributes = MSADUser.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			# TODO: return ldapuser object
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')

	def get_user(self, sAMAccountName):
		"""
		Fetches one user object from the AD, based on the sAMAccountName attribute (read: username) 
		"""
		logger.debug('Polling AD for user %s'% sAMAccountName)
		ldap_filter = r'(&(objectClass=user)(sAMAccountName=%s)' % sAMAccountName
		attributes = MSADUser.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			# TODO: return ldapuser object
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')

	def get_ad_info(self):
		"""
		Polls for basic AD information (needed for determine password usage characteristics!)
		"""
		logger.debug('Polling AD for basic info')
		ldap_filter = r'(distinguishedName=%s)' % self._tree
		attributes = MSADInfo.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			self._ldapinfo = MSADInfo.from_ldap(entry)
			return self._ldapinfo

		logger.debug('Poll finished!')

	def get_all_service_user_objects(self, include_machine = False):
		"""
		Fetches all service user objects from the AD, and returns MSADUser object.
		Service user refers to an user whith SPN (servicePrincipalName) attribute set
		"""
		logger.debug('Polling AD for all user objects, machine accounts included: %s'% include_machine)
		if include_machine == True:
			ldap_filter = r'(servicePrincipalName=*)'
		else:
			ldap_filter = r'(&(servicePrincipalName=*)(!(sAMAccountName = *$)))'

		attributes = MSADUser.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			# TODO: return ldapuser object
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')

	def get_all_knoreq_user_objects(self, include_machine = False):
		"""
		Fetches all user objects with useraccountcontrol DONT_REQ_PREAUTH flag set from the AD, and returns MSADUser object.
		
		"""
		logger.debug('Polling AD for all user objects, machine accounts included: %s'% include_machine)
		if include_machine == True:
			ldap_filter = r'(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
		else:
			ldap_filter = r'(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(sAMAccountName = *$)))'

		attributes = MSADUser.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			# TODO: return ldapuser object
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')
