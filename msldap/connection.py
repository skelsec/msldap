#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, BASE, ALL_ATTRIBUTES, LEVEL
from ldap3.utils.conv import escape_filter_chars

from msldap import logger
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest, SDFlagsRequestValue
from msldap.wintypes.security_descriptor import SECURITY_DESCRIPTOR
from msldap.wintypes.sid import SID

from msldap.ldap_objects import *
from msldap.network.proxy.handler import Proxyhandler
from msldap.authentication.handler import AuthHandler


class MSLDAPConnection:
	def __init__(self, login_credential, target_server, ldap_query_page_size = 1000):
		self.login_credential = login_credential
		self.target = target_server
		self.auth_handler = AuthHandler(self.login_credential, self.target)
		self.proxy_handler = Proxyhandler(self.target)

		self.ldap_query_page_size = ldap_query_page_size #default for MSAD
		self._tree = None
		self._ldapinfo = None
		self._srv = None
		self._con = None
		

	def connect(self):
		if self._con is not None:
			logger.debug('Already connected!')
			return

		try:
			#setting up authentication
			self.login_credential = self.auth_handler.select()

			#setting up connection
			self.target = self.proxy_handler.select()
			self._tree = self.target.tree
		except Exception as e:
			logger.exception('Failed getting authentication or target to work.')
			return False

		if self.login_credential.is_anonymous() == True:
			logger.debug('Getting server info via Anonymous BIND on server %s' % self.target.get_host())
			self._srv = Server(self.target.get_host(), use_ssl=self.target.is_ssl(), get_info=ALL)
			self._con = Connection(
				self._srv, 
				receive_timeout = self.target.timeout, 
				auto_bind=True
			)
		else:
			self._srv = Server(self.target.get_host(), use_ssl=self.target.is_ssl(), get_info=ALL)			
			self._con = Connection(
				self._srv, 
				user=self.login_credential.get_msuser(), 
				password=self.login_credential.password, 
				authentication=self.login_credential.get_authmethod(), 
				receive_timeout = self.target.timeout, 
				auto_bind=True
			)
			logger.debug('Performing BIND to server %s' % self.target.get_host())
		
		if not self._con.bind():
			if 'description' in self._con.result:
				raise Exception('Failed to bind to server! Reason: %s' % self._con.result['description'])
			raise Exception('Failed to bind to server! Reason: %s' % self._con.result)
		
		if not self._tree:
			logger.debug('Search tree base not defined, selecting root tree')
			info = self.get_server_info()
			if 'defaultNamingContext' not in info.other:
				#really rare cases, the DC doesnt reply to DSA requests!!!
				#in this case you will need to manually instruct the connection object on which tree it should perform the searches on	
				raise Exception('Could not get the defaultNamingContext! You will need to specify the "tree" parameter manually!')
			
			self._tree = info.other['defaultNamingContext'][0]
			logger.debug('Selected tree: %s' % self._tree)
		
		
		logger.debug('Connected to server!')
		return True

	def get_server_info(self):
		"""
		Performs bind on the server and grabs the DSA info object.
		If anonymous is set to true, then it will perform anonymous bind, not using user credentials
		Otherwise it will use the credentials set in the object constructor.
		"""
		if not self._con:
			self.connect()
		return self._srv.info

	def pagedsearch(self, ldap_filter, attributes, controls = None):
		"""
		Performs a paged search on the AD, using the filter and attributes as a normal query does.
		Needs to connect to the server first!
		ldap_filter: str : LDAP query filter
		attributes: list : Attributes list to recieve in the result
		"""
		logger.debug('Paged search, filter: %s attributes: %s' % (ldap_filter, ','.join(attributes)))
		ctr = 0
		#entries = 
		for entry in self._con.extend.standard.paged_search(
			self._tree, 
			ldap_filter, 
			attributes = attributes, 
			paged_size = self.ldap_query_page_size, 
			controls = controls, 
			generator=True
			):
				if 'raw_attributes' in entry and 'attributes' in entry:
					# TODO: return ldapuser object
					ctr += 1
					if ctr % self.ldap_query_page_size == 0:
						logger.debug('New page requested. Result count: %d' % ctr)
					yield entry

	def get_tree_plot(self, dn, level = 2):
		logger.debug('Tree, dn: %s level: %s' % (dn, level))
		tree = {}
		#entries = 
		for entry in self._con.extend.standard.paged_search(
			dn, 
			'(distinguishedName=*)', 
			attributes = 'distinguishedName', 
			paged_size = self.ldap_query_page_size, 
			search_scope=LEVEL, 
			controls = None, 
			generator=True
			):
			
				if 'raw_attributes' in entry and 'attributes' in entry:
					# TODO: return ldapuser object
					if level == 0:
						return {}
					
					#print(entry['attributes']['distinguishedName'])
					if entry['attributes']['distinguishedName'] is None or entry['attributes']['distinguishedName'] == []:
						continue
					subtree = self.get_tree_plot(entry['attributes']['distinguishedName'], level = level -1)
					tree[entry['attributes']['distinguishedName']] = subtree
		return {dn : tree}


	def get_all_user_objects(self):
		"""
		Fetches all user objects from the AD, and returns MSADUser object
		"""
		logger.debug('Polling AD for all user objects')
		ldap_filter = r'(sAMAccountType=805306368)'

		attributes = MSADUser.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')

	def get_all_machine_objects(self):
		"""
		Fetches all machine objects from the AD, and returns MSADMachine object
		"""
		logger.debug('Polling AD for all user objects')
		ldap_filter = r'(sAMAccountType=805306369)'

		attributes = MSADMachine.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			yield MSADMachine.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')
	
	def get_all_gpos(self):
		ldap_filter = r'(objectCategory=groupPolicyContainer)'
		attributes = MSADGPO.ATTRS
		for entry in self.pagedsearch(ldap_filter, attributes):
			yield MSADGPO.from_ldap(entry)

	def get_all_laps(self):
		ldap_filter = r'(sAMAccountType=805306369)'
		attributes = ['cn','ms-mcs-AdmPwd']
		for entry in self.pagedsearch(ldap_filter, attributes):
			yield entry

	def get_laps(self, sAMAccountName):
		ldap_filter = r'(&(sAMAccountType=805306369)(sAMAccountName=%s))' % sAMAccountName
		attributes = ['cn','ms-mcs-AdmPwd']
		for entry in self.pagedsearch(ldap_filter, attributes):
			yield entry

	def get_user(self, sAMAccountName):
		"""
		Fetches one user object from the AD, based on the sAMAccountName attribute (read: username) 
		"""
		logger.debug('Polling AD for user %s'% sAMAccountName)
		ldap_filter = r'(&(objectClass=user)(sAMAccountName=%s))' % sAMAccountName
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
		
		ldap_filter = r'(distinguishedName=%s)' % escape_filter_chars(dn)
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
			
	def get_all_ous(self):
		ldap_filter = r'(objectClass=organizationalUnit)'
		for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			yield MSADOU.from_ldap(entry)
			
	def get_group_by_dn(self, dn):
		ldap_filter = r'(&(objectClass=group)(distinguishedName=%s))' % escape_filter_chars(dn)
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
		ldap_filter = r'(distinguishedName=%s)' % escape_filter_chars(dn)
		attributes=['tokenGroups']
		
		#self._con.search(dn, ldap_filter, attributes=attributes, search_scope=BASE)
		#for entry in self._con.response:
		#	if entry['attributes']['tokenGroups']:
		#		for sid_data in entry['attributes']['tokenGroups']:
		#			yield str(SID.from_bytes(sid_data))

		#entries = 
		for entry in self._con.extend.standard.paged_search(
			dn, 
			ldap_filter, 
			attributes = attributes, 
			paged_size = self.ldap_query_page_size, 
			search_scope=BASE, 
			generator=True
			):
				if entry['attributes']['tokenGroups']:
					for sid_data in entry['attributes']['tokenGroups']:
						yield str(SID.from_bytes(sid_data))
			