#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import getpass
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, BASE, ALL_ATTRIBUTES

from msldap.core.ms_asn1 import *
from msldap.core.win_data_types import *

from msldap import logger
from ..ldap_objects import *

class MSLDAPUserCredential:
	def __init__(self, domain=None, username= None, password = None, is_ntlm = False):
		self.domain   = domain
		self.username = username
		self.password = password
		self.is_ntlm = is_ntlm

		if username.find('\\') != -1:
			self.domain, self.username = username.split('\\')

		#if not self.domain:
		#	raise Exception('Domain needs to be set, either via the "domain" parameter or by supplying the full username in "DOMAIN\\\\Username format"')

	def get_msuser(self):
		if not self.domain:
			return self.username

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
	def __init__(self, login_credential, target_server, ldap_query_page_size = 1000, use_sspi = False):
		self.login_credential = login_credential
		self.target_server = target_server
		self.use_sspi = use_sspi

		self.ldap_query_page_size = ldap_query_page_size #default for MSAD
		self._tree = self.target_server.tree
		self._ldapinfo = None
		self._srv = None
		self._con = None
		
	def monkeypatch(self):
		#print('Monkey-patching ldap tp use SSPI module for NTLM auth!')
		try:
			from winsspi.sspi import LDAP3NTLMSSPI
			import ldap3.utils.ntlm
		except Exception as e:
			print('Failed to import winsspi module!')
			raise e
		#monkey-patching NTLM client with winsspi's implementation
		ldap3.utils.ntlm.NtlmClient = LDAP3NTLMSSPI
		return Connection(self._srv, user='test\\test', password='test', authentication=NTLM)

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
			if self.use_sspi == True:
				conn = self.monkeypatch()
			else:
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
			if self.use_sspi == True:
				self._con = self.monkeypatch()
			else:
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

	def pagedsearch(self, ldap_filter, attributes, controls = None):
		"""
		Performs a paged search on the AD, using the filter and attributes as a normal query does.
		Needs to connect to the server first!
		ldap_filter: str : LDAP query filter
		attributes: list : Attributes list to recieve in the result
		"""
		logger.debug('Paged search, filter: %s attributes: %s' % (ldap_filter, ','.join(attributes)))
		ctr = 0
		entries = self._con.extend.standard.paged_search(self._tree, ldap_filter, attributes = attributes, paged_size = self.ldap_query_page_size, controls = controls)
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
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')

	def get_all_machine_objects(self):
		"""
		Fetches all machine objects from the AD, and returns MSADMachine object
		"""
		logger.debug('Polling AD for all user objects')
		ldap_filter = r'(&(sAMAccountType=805306369))'

		attributes = MSADMachine.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			yield MSADMachine.from_ldap(entry, self._ldapinfo)
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
		
		
	def get_all_objectacl(self):
		"""
		Returns all ACL info for all AD objects
		"""
		
		flags_value = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION
		req_flags = SDFlagsRequestValue({'Flags' : flags_value})
		
		ldap_filter = r'(objectClass=*)'
		attributes = MSADSecurityInfo.ATTRS
		controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]
		
		for entry in self.pagedsearch(ldap_filter, attributes, controls = controls):
			yield MSADSecurityInfo.from_ldap(entry)
			
	def get_objectacl_by_dn(self, dn):
		"""
		Returns all ACL info for all AD objects
		"""
		
		flags_value = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION
		req_flags = SDFlagsRequestValue({'Flags' : flags_value})
		
		ldap_filter = r'(distinguishedName=%s)' % dn
		attributes = MSADSecurityInfo.ATTRS
		controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]
		
		for entry in self.pagedsearch(ldap_filter, attributes, controls = controls):
			yield MSADSecurityInfo.from_ldap(entry)

			
	def get_all_tokengroups(self):
		"""
		returns the tokengroups attribute for all user and machine on the server
		"""
		dns = []
		
		ldap_filters = [r'(objectClass=user)', r'(sAMAccountType=805306369)']
		attributes = ['distinguishedName']
		
		for ldap_filter in ldap_filters:
			print(ldap_filter)
			for entry in self.pagedsearch(ldap_filter, attributes):
				print(entry['attributes']['distinguishedName'])
				dns.append(entry['attributes']['distinguishedName'])

		attributes=['tokenGroups', 'sn', 'cn', 'distinguishedName','objectGUID', 'objectSid']
		for dn in dns:
			ldap_filter = r'(distinguishedName=%s)' % dn
			self._con.search(dn, ldap_filter, attributes=attributes, search_scope=BASE)
			for entry in self._con.response:
				#yield MSADTokenGroup.from_ldap(entry)
				print(str(MSADTokenGroup.from_ldap(entry)))
	
	def get_pdcroleowner(self):
		#http://adcoding.com/how-to-determine-the-fsmo-role-holder-fsmoroleowner-attribute/
		#get adinfo -> get ridmanagerreference attr -> look up the dn of ridmanagerreference -> get fsmoroleowner attr (which is a DN)
		if not self._ldapinfo:
			self.get_ad_info()
		
		ldap_filter = r'(distinguishedName=%s)' % self._ldapinfo.rIDManagerReference
		for entry in self.pagedsearch(ldap_filter, ['fSMORoleOwner']):
			return entry['attributes']['fSMORoleOwner']
		
	def get_infrastructureowner(self):
		#http://adcoding.com/how-to-determine-the-fsmo-role-holder-fsmoroleowner-attribute/
		#"CN=Infrastructure,DC=concorp,DC=contoso,DC=com" -l fSMORoleOwner
		if not self._ldapinfo:
			self.get_ad_info()
		
		ldap_filter = r'(distinguishedName=%s)' % ('CN=Infrastructure,' + self._ldapinfo.distinguishedName)
		for entry in self.pagedsearch(ldap_filter, ['fSMORoleOwner']):
			return entry['attributes']['fSMORoleOwner']
			
	def get_ridroleowner(self):
		#http://adcoding.com/how-to-determine-the-fsmo-role-holder-fsmoroleowner-attribute/
		if not self._ldapinfo:
			self.get_ad_info()
		
		ldap_filter = r'(distinguishedName=%s)' % ('CN=RID Manager$,CN=System,' + self._ldapinfo.distinguishedName)
		for entry in self.pagedsearch(ldap_filter, ['fSMORoleOwner']):
			return entry['attributes']['fSMORoleOwner']		
		
	
	def get_netdomain(self):
		def nameconvert(x):
			return x.split(',CN=')[1]
		"""
		gets the name of the current user's domain
		"""
		if not self._ldapinfo:
			self.get_ad_info()
		print(self._ldapinfo)
		dname = self._ldapinfo.distinguishedName.replace('DC','').replace('=','').replace(',','.')
		domain_controllers = ','.join(nameconvert(x) + '.' +dname  for x in self._ldapinfo.masteredBy)
		
		ridroleowner = nameconvert(self.get_ridroleowner()) + '.' +dname
		infraowner = nameconvert(self.get_infrastructureowner()) + '.' +dname
		pdcroleowner = nameconvert(self.get_pdcroleowner()) + '.' +dname
		
		print('name : %s' % dname)
		print('Domain Controllers : %s' % domain_controllers)
		print('DomainModeLevel : %s' % self._ldapinfo.domainmodelevel)
		print('PdcRoleOwner : %s' % pdcroleowner)
		print('RidRoleOwner : %s' % ridroleowner)
		print('InfrastructureRoleOwner : %s' % infraowner)
		
	def get_domaincontroller(self):
		ldap_filter = r'(userAccountControl:1.2.840.113556.1.4.803:=8192)'
		for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			print('Forest: %s' % '')
			print('Name: %s' % entry['attributes'].get('dNSHostName'))
			print('OSVersion: %s' % entry['attributes'].get('operatingSystem'))
			print(entry['attributes'])
		
		
	def get_all_groups(self):
		ldap_filter = r'(objectClass=group)'
		for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			yield MSADGroup.from_ldap(entry)
			
	def get_group_by_dn(self, dn):
		ldap_filter = r'(&(objectClass=group)(distinguishedName=%s))' % dn
		for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			yield MSADGroup.from_ldap(entry)
			
	def get_object_by_dn(self, dn, expected_class = None):
		ldap_filter = r'(distinguishedName=%s)' % dn
		for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			temp = entry['attributes'].get('objectClass')
			if expected_class:
				yield expected_class.from_ldap(entry)
			
			if not temp:
				yield entry
			elif 'user' in temp:
				yield MSADUser.from_ldap(entry)
			elif 'group' in temp:
				yield MSADGroup.from_ldap(entry)
			
	def get_user_by_dn(self, dn):
		ldap_filter = r'(&(objectClass=user)(distinguishedName=%s))' % dn
		for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			yield MSADUser.from_ldap(entry)
			
	def get_group_members(self, dn, recursive = False):
		for group in self.get_group_by_dn(dn):
			for member in group.member:
				for result in self.get_object_by_dn(member):
					if isinstance(result, MSADGroup) and recursive:
						for user in self.get_group_members(result.distinguishedName, recursive = True):
							yield(user)
					else:
						yield(result)
						
	def get_dn_for_objectsid(self, objectsid):
		ldap_filter = r'(objectSid=%s)' % str(objectsid)
		for entry in self.pagedsearch(ldap_filter, ['distinguishedName']):
			return entry['attributes']['distinguishedName']
						
	def get_permissions_for_dn(self, dn):
		"""
		Lists all users who can modify the specified dn
		"""
		for secinfo in self.get_objectacl_by_dn(dn):
			for secdata in secinfo.nTSecurityDescriptor:
				sids_to_lookup = {}
				sdec = SECURITY_DESCRIPTOR.from_bytes(secdata)
				if not sdec.Dacl:
					continue
				
				for ace in sdec.Dacl.aces:
					sids_to_lookup[str(ace.Sid)] = 1
				
				for sid in sids_to_lookup:
					sids_to_lookup[sid] = self.get_dn_for_objectsid(sid)
					
				print(sids_to_lookup)
				
				for ace in sdec.Dacl.aces:
					if not sids_to_lookup[str(ace.Sid)]:
						print(str(ace.Sid))
					#print('===== %s =====' % sids_to_lookup[str(ace.Sid)])
					#if 
					#print(str(ace))
					
					
					
	def get_tokengroups(self, dn):
		"""
		returns the tokengroups attribute for a given DN
		"""
		ldap_filter = r'(distinguishedName=%s)' % dn
		attributes=['tokenGroups']
		
		self._con.search(dn, ldap_filter, attributes=attributes, search_scope=BASE)
		for entry in self._con.response:
			if entry['attributes']['tokenGroups']:
				for sid_data in entry['attributes']['tokenGroups']:
					yield str(SID.from_bytes(sid_data))
			