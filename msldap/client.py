#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from msldap import logger
from msldap.commons.common import MSLDAPClientStatus
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest, SDFlagsRequestValue
from msldap.protocol.constants import BASE, ALL_ATTRIBUTES, LEVEL

from msldap.protocol.query import escape_filter_chars, query_syntax_converter
from msldap.connection import MSLDAPClientConnection
from msldap.protocol.messages import Control
from msldap.ldap_objects import *

class MSLDAPClient:
	def __init__(self, target, creds, ldap_query_page_size = 1000):
		self.creds = creds
		self.target = target

		self.ldap_query_page_size = ldap_query_page_size 
		self._tree = None
		self._ldapinfo = None
		self._con = None
		

	async def connect(self):
		self._con = MSLDAPClientConnection(self.target, self.creds)
		await self._con.connect()
		res, err = await self._con.bind()
		if err is not None:
			return False, err
		res, err = await self._con.get_serverinfo()
		if err is not None:
			raise err
		self._serverinfo = res
		self._tree = res['defaultNamingContext']
		self._ldapinfo = await self.get_ad_info()
		return True, None

	def get_server_info(self):
		return self._serverinfo

	async def pagedsearch(self, ldap_filter, attributes, controls = None):
		"""
		Performs a paged search on the AD, using the filter and attributes as a normal query does.
		Needs to connect to the server first!

		Parameters:
			ldap_filter (str): LDAP query filter
			attributes (list): Attributes list to recieve in the result
			controls (obj): Additional control dict
		
		Returns:
			generator
		"""
		logger.debug('Paged search, filter: %s attributes: %s' % (ldap_filter, ','.join(attributes)))
		if self._con.status != MSLDAPClientStatus.RUNNING:
			if self._con.status == MSLDAPClientStatus.ERROR:
				print('There was an error in the connection!')
				return
			elif self._con.status == MSLDAPClientStatus.ERROR:
				print('Theconnection is in stopped state!')
				return

		if self._tree is None:
			raise Exception('BIND first!')
		t = []
		for x in attributes:
			t.append(x.encode())
		attributes = t
		ldap_filter = query_syntax_converter(ldap_filter)

		t = []
		if controls is not None:
			for control in controls:
				t.append(Control({
					'controlType': control[0].encode(),
					'criticality': control[1],
					'controlValue': control[2]
				}))

		controls = t

		async for entry, err in self._con.pagedsearch(
			self._tree.encode(), 
			ldap_filter, 
			attributes = attributes, 
			paged_size = self.ldap_query_page_size, 
			controls = controls
			):
				
				if err is not None:
					raise err
				if entry['objectName'] == '' and entry['attributes'] == '':
					#searchresref...
					continue
				#print('et %s ' % entry)
				yield entry

	async def get_tree_plot(self, dn, level = 2):
		"""
		Returns a dictionary representing a tree starting from 'dn' containing all subtrees.
		Parameters:
			dn (str): Distinguished name of the root of the tree
			level (int): Recursion level
		Returns:
			dict
		"""
		logger.debug('Tree, dn: %s level: %s' % (dn, level))
		tree = {}
		#entries = 
		async for entry, err in self._con.pagedsearch(
			dn.encode(), 
			query_syntax_converter('(distinguishedName=*)'), 
			attributes = [b'distinguishedName'], 
			paged_size = self.ldap_query_page_size, 
			search_scope=LEVEL, 
			controls = None, 
			):
				if err is not None:
					raise err

				if level == 0:
					return {}
				#print(entry)
				#print(entry['attributes']['distinguishedName'])
				if 'distinguishedName' not in entry['attributes'] or entry['attributes']['distinguishedName'] is None or entry['attributes']['distinguishedName'] == []:
					continue
				subtree = await self.get_tree_plot(entry['attributes']['distinguishedName'], level = level -1)
				tree[entry['attributes']['distinguishedName']] = subtree
		return {dn : tree}


	async def get_all_user_objects(self):
		"""
		Fetches all user objects from the AD, and returns MSADUser object
		"""
		logger.debug('Polling AD for all user objects')
		ldap_filter = r'(sAMAccountType=805306368)'
		async for entry in self.pagedsearch(ldap_filter, MSADUser_ATTRS):
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')

	async def get_all_user_raw(self):
		"""
		Fetches all user objects from the AD, and returns MSADUser object
		"""
		logger.debug('Polling AD for all user objects')
		ldap_filter = r'(sAMAccountType=805306368)'

		return self.pagedsearch(ldap_filter, MSADUser_ATTRS)

	async def get_all_machine_objects(self):
		"""
		Fetches all machine objects from the AD, and returns MSADMachine object
		"""
		logger.debug('Polling AD for all user objects')
		ldap_filter = r'(sAMAccountType=805306369)'

		async for entry in self.pagedsearch(ldap_filter, MSADMachine_ATTRS):
			yield MSADMachine.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')
	
	async def get_all_gpos(self):
		ldap_filter = r'(objectCategory=groupPolicyContainer)'
		async for entry in self.pagedsearch(ldap_filter, MSADGPO_ATTRS):
			yield MSADGPO.from_ldap(entry)

	async def get_all_laps(self):
		ldap_filter = r'(sAMAccountType=805306369)'
		attributes = ['cn','ms-mcs-AdmPwd']
		async for entry in self.pagedsearch(ldap_filter, attributes):
			yield entry

	async def get_laps(self, sAMAccountName):
		ldap_filter = r'(&(sAMAccountType=805306369)(sAMAccountName=%s))' % sAMAccountName
		attributes = ['cn','ms-mcs-AdmPwd']
		async for entry in self.pagedsearch(ldap_filter, attributes):
			yield entry

	async def get_user(self, sAMAccountName):
		"""
		Fetches one user object from the AD, based on the sAMAccountName attribute (read: username) 
		"""
		logger.debug('Polling AD for user %s'% sAMAccountName)
		ldap_filter = r'(&(objectClass=user)(sAMAccountName=%s))' % sAMAccountName
		async for entry in self.pagedsearch(ldap_filter, MSADUser_ATTRS):
			# TODO: return ldapuser object
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')

	async def get_ad_info(self):
		"""
		Polls for basic AD information (needed for determine password usage characteristics!)
		"""
		logger.debug('Polling AD for basic info')
		ldap_filter = r'(distinguishedName=%s)' % self._tree
		async for entry in self.pagedsearch(ldap_filter, MSADInfo_ATTRS):
			self._ldapinfo = MSADInfo.from_ldap(entry)
			return self._ldapinfo

		logger.debug('Poll finished!')

	async def get_all_spn_entries(self):
		logger.debug('Polling AD for all SPN entries')
		ldap_filter = r'(&(sAMAccountType=805306369))'
		attributes = ['objectSid','sAMAccountName', 'servicePrincipalName']

		async for entry in self.pagedsearch(ldap_filter, attributes):
			yield entry

	async def get_all_service_user_objects(self, include_machine = False):
		"""
		Fetches all service user objects from the AD, and returns MSADUser object.
		Service user refers to an user whith SPN (servicePrincipalName) attribute set
		"""
		logger.debug('Polling AD for all user objects, machine accounts included: %s'% include_machine)
		if include_machine == True:
			ldap_filter = r'(servicePrincipalName=*)'
		else:
			ldap_filter = r'(&(servicePrincipalName=*)(!(sAMAccountName=*$)))'

		async for entry in self.pagedsearch(ldap_filter, MSADUser_ATTRS):
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')

	async def get_all_knoreq_user_objects(self, include_machine = False):
		"""
		Fetches all user objects with useraccountcontrol DONT_REQ_PREAUTH flag set from the AD, and returns MSADUser object.
		
		"""
		logger.debug('Polling AD for all user objects, machine accounts included: %s'% include_machine)
		if include_machine == True:
			ldap_filter = r'(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
		else:
			ldap_filter = r'(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(sAMAccountName=*$)))'

		async for entry in self.pagedsearch(ldap_filter, MSADUser_ATTRS):
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')
		
		
	#async def get_all_objectacl(self):
	#	"""
	#	Returns all ACL info for all AD objects
	#	"""
	#	
	#	flags_value = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION
	#	req_flags = SDFlagsRequestValue({'Flags' : flags_value})
	#	
	#	ldap_filter = r'(objectClass=*)'
	#	attributes = MSADSecurityInfo.ATTRS
	#	controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]
	#	
	#	async for entry in self.pagedsearch(ldap_filter, attributes, controls = controls):
	#		yield MSADSecurityInfo.from_ldap(entry)
			
	async def get_objectacl_by_dn(self, dn):
		"""
		Returns all ACL info for all AD objects
		"""
		
		flags_value = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION
		req_flags = SDFlagsRequestValue({'Flags' : flags_value})
		
		ldap_filter = r'(distinguishedName=%s)' % escape_filter_chars(dn)
		attributes = MSADSecurityInfo.ATTRS
		controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]
		
		async for entry in self.pagedsearch(ldap_filter, attributes, controls = controls):
			yield MSADSecurityInfo.from_ldap(entry)

			
	#async def get_all_tokengroups(self):
	#	"""
	#	returns the tokengroups attribute for all user and machine on the server
	#	"""
	#	dns = []
	#	
	#	ldap_filters = [r'(objectClass=user)', r'(sAMAccountType=805306369)']
	#	attributes = ['distinguishedName']
	#	
	#	for ldap_filter in ldap_filters:
	#		print(ldap_filter)
	#		for entry in self.pagedsearch(ldap_filter, attributes):
	#			print(entry['attributes']['distinguishedName'])
	#			dns.append(entry['attributes']['distinguishedName'])
	#
	#	attributes=['tokenGroups', 'sn', 'cn', 'distinguishedName','objectGUID', 'objectSid']
	#	for dn in dns:
	#		ldap_filter = r'(distinguishedName=%s)' % dn
	#		self._con.search(dn, ldap_filter, attributes=attributes, search_scope=BASE)
	#		async for entry, err in self._con.response:
	#			#yield MSADTokenGroup.from_ldap(entry)
	#			print(str(MSADTokenGroup.from_ldap(entry)))
	
	async def get_pdcroleowner(self):
		#http://adcoding.com/how-to-determine-the-fsmo-role-holder-fsmoroleowner-attribute/
		#get adinfo -> get ridmanagerreference attr -> look up the dn of ridmanagerreference -> get fsmoroleowner attr (which is a DN)
		if not self._ldapinfo:
			self.get_ad_info()
		
		ldap_filter = r'(distinguishedName=%s)' % self._ldapinfo.rIDManagerReference
		async for entry in self.pagedsearch(ldap_filter, ['fSMORoleOwner']):
			return entry['attributes']['fSMORoleOwner']
		
	async def get_infrastructureowner(self):
		#http://adcoding.com/how-to-determine-the-fsmo-role-holder-fsmoroleowner-attribute/
		#"CN=Infrastructure,DC=concorp,DC=contoso,DC=com" -l fSMORoleOwner
		if not self._ldapinfo:
			self.get_ad_info()
		
		ldap_filter = r'(distinguishedName=%s)' % ('CN=Infrastructure,' + self._ldapinfo.distinguishedName)
		async for entry in self.pagedsearch(ldap_filter, ['fSMORoleOwner']):
			return entry['attributes']['fSMORoleOwner']
			
	async def get_ridroleowner(self):
		#http://adcoding.com/how-to-determine-the-fsmo-role-holder-fsmoroleowner-attribute/
		if not self._ldapinfo:
			self.get_ad_info()
		
		ldap_filter = r'(distinguishedName=%s)' % ('CN=RID Manager$,CN=System,' + self._ldapinfo.distinguishedName)
		async for entry in self.pagedsearch(ldap_filter, ['fSMORoleOwner']):
			return entry['attributes']['fSMORoleOwner']		
		
	
	async def get_netdomain(self):
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
		
	async def get_domaincontroller(self):
		ldap_filter = r'(userAccountControl:1.2.840.113556.1.4.803:=8192)'
		async for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			print('Forest: %s' % '')
			print('Name: %s' % entry['attributes'].get('dNSHostName'))
			print('OSVersion: %s' % entry['attributes'].get('operatingSystem'))
			print(entry['attributes'])
		
		
	async def get_all_groups(self):
		ldap_filter = r'(objectClass=group)'
		async for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			yield MSADGroup.from_ldap(entry)
			
	async def get_all_ous(self):
		ldap_filter = r'(objectClass=organizationalUnit)'
		async for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			yield MSADOU.from_ldap(entry)
			
	async def get_group_by_dn(self, dn):
		ldap_filter = r'(&(objectClass=group)(distinguishedName=%s))' % escape_filter_chars(dn)
		async for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			yield MSADGroup.from_ldap(entry)
			
	async def get_object_by_dn(self, dn, expected_class = None):
		ldap_filter = r'(distinguishedName=%s)' % dn
		async for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			temp = entry['attributes'].get('objectClass')
			if expected_class:
				yield expected_class.from_ldap(entry)
			
			if not temp:
				yield entry
			elif 'user' in temp:
				yield MSADUser.from_ldap(entry)
			elif 'group' in temp:
				yield MSADGroup.from_ldap(entry)
			
	async def get_user_by_dn(self, dn):
		ldap_filter = r'(&(objectClass=user)(distinguishedName=%s))' % dn
		async for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			yield MSADUser.from_ldap(entry)
			
	async def get_group_members(self, dn, recursive = False):
		async for group in self.get_group_by_dn(dn):
			for member in group.member:
				async for result in self.get_object_by_dn(member):
					if isinstance(result, MSADGroup) and recursive:
						async for user in self.get_group_members(result.distinguishedName, recursive = True):
							yield(user)
					else:
						yield(result)
						
	async def get_dn_for_objectsid(self, objectsid):
		ldap_filter = r'(objectSid=%s)' % str(objectsid)
		async for entry in self.pagedsearch(ldap_filter, ['distinguishedName']):
			return entry['attributes']['distinguishedName']
						
	async def get_permissions_for_dn(self, dn):
		"""
		Lists all users who can modify the specified dn
		"""
		async for secinfo in self.get_objectacl_by_dn(dn):
			for sdec in secinfo.nTSecurityDescriptor:
				sids_to_lookup = {}
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
					
					
					
	async def get_tokengroups(self, dn):
		"""
		returns the tokengroups attribute for a given DN
		"""
		ldap_filter = query_syntax_converter( r'(distinguishedName=%s)' % escape_filter_chars(dn) )
		attributes=[b'tokenGroups']

		async for entry, err in self._con.pagedsearch(
			dn.encode(), 
			ldap_filter, 
			attributes = attributes, 
			paged_size = self.ldap_query_page_size, 
			search_scope=BASE, 
			):
				if err is not None:
					yield None, err
					break
				
				#print(entry['attributes'])
				if 'tokenGroups' in entry:
					for sid_data in entry['tokenGroups']:
						yield sid_data
			
	async def get_all_tokengroups(self):
		"""
		returns the tokengroups attribute for a given DN
		"""
		ldap_filter = r'(|(sAMAccountType=805306369)(objectClass=group)(sAMAccountType=805306368))'
		async for entry in self.pagedsearch(
			ldap_filter, 
			attributes = ['dn', 'cn', 'objectSid','objectClass', 'objectGUID']
			):				

				if 'objectName' in entry:
					#print(entry['objectName'])
					async for entry2, err in self._con.pagedsearch(
						entry['objectName'].encode(), 
						query_syntax_converter( r'(distinguishedName=%s)' % escape_filter_chars(entry['objectName']) ), 
						attributes = [b'tokenGroups'], 
						paged_size = self.ldap_query_page_size, 
						search_scope=BASE, 
						):
							
							#print(entry2)
							if err is not None:
								yield None, err
								break
							if 'tokenGroups' in entry2['attributes']:
								for token in entry2['attributes']['tokenGroups']:
									yield {
										'cn' : entry['attributes']['cn'],
										'dn' : entry['objectName'],
										'guid' : entry['attributes']['objectGUID'],
										'sid' : entry['attributes']['objectSid'],
										'type' : entry['attributes']['objectClass'][-1],
										'token' : token

									}

	async def get_all_objectacl(self):
		"""
		bbbbbb
		"""
		
		flags_value = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION
		req_flags = SDFlagsRequestValue({'Flags' : flags_value})
		
		ldap_filter = r'(|(objectClass=organizationalUnit)(objectCategory=groupPolicyContainer)(sAMAccountType=805306369)(objectClass=group)(sAMAccountType=805306368))'
		async for entry in self.pagedsearch(ldap_filter, attributes = ['dn']):
			ldap_filter = r'(distinguishedName=%s)' % escape_filter_chars(entry['objectName'])
			attributes = MSADSecurityInfo.ATTRS
			controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]
			
			async for entry2 in self.pagedsearch(ldap_filter, attributes, controls = controls):
				yield MSADSecurityInfo.from_ldap(entry2)


	async def get_all_trusts(self):
		ldap_filter = r'(objectClass=trustedDomain)'
		async for entry in self.pagedsearch(ldap_filter, attributes = MSADDomainTrust_ATTRS):
			yield MSADDomainTrust.from_ldap(entry)