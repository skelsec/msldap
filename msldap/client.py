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
	"""
	High level API for LDAP operations.

	target, creds, ldap_query_page_size

	:param target: The target object describing the connection info
	:type target: :class:`MSLDAPTarget`
	:param creds: The credential object describing the authentication to be used
	:type creds: :class:`MSLDAPCredential`
	:param ldap_query_page_size: 
	:type ldap_query_page_size: int
	:return: A dictionary representing the LDAP tree
	:rtype: dict

	"""
	def __init__(self, target, creds, ldap_query_page_size = 1000):
		self.creds = creds
		self.target = target

		self.ldap_query_page_size = ldap_query_page_size 
		self._tree = None
		self._ldapinfo = None
		self._con = None
		

	async def connect(self):
		self._con = MSLDAPClientConnection(self.target, self.creds)
		_, err = await self._con.connect()
		if err is not None:
			raise err
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
			!The LDAP connection MUST be active before invoking this function!

		:param ldap_filter: LDAP query filter
		:type ldap_filter: str
		:param attributes: List of requested attributes
		:type attributes: List[str]
		:param controls: additional controls to be passed in the query
		:type controls: dict
		:param level: Recursion level
		:type level: int

		:return: A dictionary representing the LDAP tree
		:rtype: dict

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

	async def get_tree_plot(self, root_dn, level = 2):
		"""
		Returns a dictionary representing a tree starting from 'dn' containing all subtrees.

		:param root_dn: The start DN of the tree
		:type root_dn: str
		:param level: Recursion level
		:type level: int

		:return: A dictionary representing the LDAP tree
		:rtype: dict
		"""

		logger.debug('Tree, dn: %s level: %s' % (root_dn, level))
		tree = {}
		async for entry, err in self._con.pagedsearch(
			root_dn.encode(), 
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
		return {root_dn : tree}

	async def get_all_users(self):
		"""
		Fetches all user objects available in the LDAP tree and yields them as MSADUser object.
		
		:return: Async generator which yields `MSADUser` objects
		:rtype: Iterator[:class:`MSADUser`]
		
		"""
		logger.debug('Polling AD for all user objects')
		ldap_filter = r'(sAMAccountType=805306368)'
		async for entry in self.pagedsearch(ldap_filter, MSADUser_ATTRS):
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')

	async def get_all_machines(self):
		"""
		Fetches all machine objects available in the LDAP tree and yields them as MSADMachine object.
		
		:return: Async generator which yields `MSADMachine` objects
		:rtype: Iterator[:class:`MSADMachine`]
		
		"""
		logger.debug('Polling AD for all user objects')
		ldap_filter = r'(sAMAccountType=805306369)'

		async for entry in self.pagedsearch(ldap_filter, MSADMachine_ATTRS):
			yield MSADMachine.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')
	
	async def get_all_gpos(self):
		"""
		Fetches all GPOs available in the LDAP tree and yields them as MSADGPO object.
		
		:return: Async generator which yields `MSADGPO` objects
		:rtype: Iterator[:class:`MSADGPO`]
		
		"""

		ldap_filter = r'(objectCategory=groupPolicyContainer)'
		async for entry in self.pagedsearch(ldap_filter, MSADGPO_ATTRS):
			yield MSADGPO.from_ldap(entry)

	async def get_all_laps(self):
		"""
		Fetches all LAPS passwords for all machines. This functionality is only available to specific high-privileged users.
		
		:return: The user as `MSADUser`
		:rtype: :class:`MSADUser`
		"""

		ldap_filter = r'(sAMAccountType=805306369)'
		attributes = ['cn','ms-mcs-AdmPwd']
		async for entry in self.pagedsearch(ldap_filter, attributes):
			yield entry

	async def get_laps(self, sAMAccountName):
		"""
		Fetches the LAPS password for a machine. This functionality is only available to specific high-privileged users.
		
		:param sAMAccountName: The username of the machine (eg. `COMP123$`).
		:type sAMAccountName: str
		:return: The user as `MSADUser`
		:rtype: Iterator[:class:`str`]
		"""

		ldap_filter = r'(&(sAMAccountType=805306369)(sAMAccountName=%s))' % sAMAccountName
		attributes = ['cn','ms-mcs-AdmPwd']
		async for entry in self.pagedsearch(ldap_filter, attributes):
			yield entry

	async def get_user(self, sAMAccountName):
		"""
		Fetches one user object from the AD, based on the sAMAccountName attribute (read: username) 
		
		:param sAMAccountName: The username of the user.
		:type sAMAccountName: str
		:return: The user as `MSADUser`
		:rtype: :class:`MSADUser`
		"""
		logger.debug('Polling AD for user %s'% sAMAccountName)
		ldap_filter = r'(&(objectClass=user)(sAMAccountName=%s))' % sAMAccountName
		async for entry in self.pagedsearch(ldap_filter, MSADUser_ATTRS):
			return MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')

	async def get_ad_info(self):
		"""
		Polls for basic AD information (needed for determine password usage characteristics!)
		
		:return: The domain information as `MSADInfo`
		:rtype: :class:`MSADInfo`
		"""
		logger.debug('Polling AD for basic info')
		ldap_filter = r'(distinguishedName=%s)' % self._tree
		async for entry in self.pagedsearch(ldap_filter, MSADInfo_ATTRS):
			self._ldapinfo = MSADInfo.from_ldap(entry)
			return self._ldapinfo

		logger.debug('Poll finished!')

	async def get_all_spn_entries(self):
		"""
		Fetches all service user objects from the AD, and returns MSADUser object.
		Service user refers to an user with SPN (servicePrincipalName) attribute set

		:param include_machine: Specifies wether machine accounts should be included in the query
		:type include_machine: bool
		:return: Async generator which yields string in SPN format
		:rtype: Iterator[:class:`str`]
		
		"""

		logger.debug('Polling AD for all SPN entries')
		ldap_filter = r'(&(sAMAccountType=805306369))'
		attributes = ['objectSid','sAMAccountName', 'servicePrincipalName']

		async for entry in self.pagedsearch(ldap_filter, attributes):
			yield entry

	async def get_all_service_user_objects(self, include_machine = False):
		"""
		Fetches all service user objects from the AD, and returns MSADUser object.
		Service user refers to an user with SPN (servicePrincipalName) attribute set

		:param include_machine: Specifies wether machine accounts should be included in the query
		:type include_machine: bool
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: Iterator[:class:`MSADUser`]

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
		
		:param include_machine: Specifies wether machine accounts should be included in the query
		:type include_machine: bool
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: Iterator[:class:`MSADUser`]

		"""
		logger.debug('Polling AD for all user objects, machine accounts included: %s'% include_machine)
		if include_machine == True:
			ldap_filter = r'(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
		else:
			ldap_filter = r'(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(sAMAccountName=*$)))'

		async for entry in self.pagedsearch(ldap_filter, MSADUser_ATTRS):
			yield MSADUser.from_ldap(entry, self._ldapinfo)
		logger.debug('Finished polling for entries!')
			
	async def get_objectacl_by_dn_p(self, dn, flags = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION):
		"""
		Returns the full or partial Security Descriptor of the object specified by it's DN.
		The flags indicate which part of the security Descriptor to be returned.
		By default the full SD info is returned.

		:param object_dn: The object's DN
		:type object_dn: str
		:param flags: Flags indicate the data type to be returned.
		:type flags: :class:`SDFlagsRequest`
		:return: 
		:rtype: :class:`MSADSecurityInfo`

		"""
		
		req_flags = SDFlagsRequestValue({'Flags' : flags})
		
		ldap_filter = r'(distinguishedName=%s)' % escape_filter_chars(dn)
		attributes = MSADSecurityInfo.ATTRS
		controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]
		
		async for entry in self.pagedsearch(ldap_filter, attributes, controls = controls):
			yield MSADSecurityInfo.from_ldap(entry)

	async def get_objectacl_by_dn(self, dn, flags = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION):
		"""
		Returns the full or partial Security Descriptor of the object specified by it's DN.
		The flags indicate which part of the security Descriptor to be returned.
		By default the full SD info is returned.

		:param object_dn: The object's DN
		:type object_dn: str
		:param flags: Flags indicate the data type to be returned.
		:type flags: :class:`SDFlagsRequest`
		:return: nTSecurityDescriptor attribute of the object
		:rtype: bytes

		"""
		
		req_flags = SDFlagsRequestValue({'Flags' : flags})
		
		ldap_filter = r'(distinguishedName=%s)' % escape_filter_chars(dn)
		attributes = ['nTSecurityDescriptor']
		controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]
		
		async for entry in self.pagedsearch(ldap_filter, attributes, controls = controls):
			return entry['attributes'].get('nTSecurityDescriptor')

	async def set_objectacl_by_dn(self, object_dn, data, flags = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION):
		"""
		Updates the security descriptor of the LDAP object
		
		:param object_dn: The object's DN
		:type object_dn: str
		:param data: The actual data as bytearray to be updated in the Security Descriptor of the specified object 
		:type data: bytes
		:param flags: Flags indicate the data type to be updated.
		:type flags: :class:`SDFlagsRequest`
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: tuple

		"""
		
		req_flags = SDFlagsRequestValue({'Flags' : flags})
		controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]

		changes = {
			'nTSecurityDescriptor': [('replace', [data])]
		}
		return await self._con.modify(object_dn, changes, controls = controls)		
		
	async def get_all_groups(self):
		"""
		Yields all Groups present in the LDAP tree.  
		
		:return: Async generator yielding the available groups with full information
		:rtype: Iterator[:class:`MSADGroup`]
		"""
		ldap_filter = r'(objectClass=group)'
		async for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			yield MSADGroup.from_ldap(entry)
			
	async def get_all_ous(self):
		"""
		Yields all OUs present in the LDAP tree.  

		:return: Async generator yielding the available OUs with full information
		:rtype: Iterator[:class:`MSADOU`]
		"""
		ldap_filter = r'(objectClass=organizationalUnit)'
		async for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			yield MSADOU.from_ldap(entry)
			
	async def get_group_by_dn(self, group_dn):
		"""
		Returns an `MSADGroup` object for the group specified by group_dn

		:param group_dn: The user's DN
		:type group_dn: str
		:return: The distinguishedName
		:rtype: :class:`MSADDomainTrust`
		"""

		ldap_filter = r'(&(objectClass=group)(distinguishedName=%s))' % escape_filter_chars(group_dn)
		async for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			return MSADGroup.from_ldap(entry)
			
	async def get_user_by_dn(self, user_dn):
		"""
		Fetches the DN for an object specified by `objectsid`

		:param user_dn: The user's DN
		:type user_dn: str
		:return: The distinguishedName
		:rtype: str
		"""

		ldap_filter = r'(&(objectClass=user)(distinguishedName=%s))' % user_dn
		async for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			yield MSADUser.from_ldap(entry)
			
	async def get_group_members(self, dn, recursive = False):
		"""
		Fetches the DN for an object specified by `objectsid`

		:param objectsid: The object's SID
		:type objectsid: str
		:return: The distinguishedName
		:rtype: str
		"""

		group = self.get_group_by_dn(dn)
		for member in group.member:
			async for result in self.get_object_by_dn(member):
				if isinstance(result, MSADGroup) and recursive:
					async for user in self.get_group_members(result.distinguishedName, recursive = True):
						yield(user)
				else:
					yield(result)
						
	async def get_dn_for_objectsid(self, objectsid):
		"""
		Fetches the DN for an object specified by `objectsid`

		:param objectsid: The object's SID
		:type objectsid: str
		:return: The distinguishedName
		:rtype: str

		"""

		ldap_filter = r'(objectSid=%s)' % str(objectsid)
		async for entry in self.pagedsearch(ldap_filter, ['distinguishedName']):
			return entry['attributes']['distinguishedName']
				
	async def get_tokengroups(self, dn):
		"""
		Yields SIDs of groups that the given DN is a member of.

		:return: Async generator that yields strings of SIDs
		:rtype: Iterator[:class:`str`]

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
		Yields all effective group membership information for all objects of the following type:
		Users, Groups, Computers

		:return: Async generator that yields dictionaries
		:rtype: Iterator[:class:`Dict`]

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
		Yields the security descriptor of all objects in the LDAP tree of the following types:  
		Users, Computers, GPOs, OUs, Groups

		:return: Async generator that yields MSADSecurityInfo
		:rtype: Iterator[:class:`MSADSecurityInfo`]

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
		"""
		Yields all trusted domains.

		:return: Async generator that yields MSADDomainTrust
		:rtype: Iterator[:class:`MSADDomainTrust`]

		"""

		ldap_filter = r'(objectClass=trustedDomain)'
		async for entry in self.pagedsearch(ldap_filter, attributes = MSADDomainTrust_ATTRS):
			yield MSADDomainTrust.from_ldap(entry)


	async def create_user(self, username, password):
		"""
		Creates a new user object with a password.
		WARNING: this function only creates the user, but will not enable it! To create a user account to be used immediately, use the `create_user_dn` function!
		
		:param user_dn: The user's DN
		:type user_dn: str
		:param password: The password of the user
		:type password: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: tuple

		"""
		user_dn = 'CN=%s,CN=Users,%s' % (username, self._tree)
		return await self.create_user_dn(user_dn, password)
		
	async def create_user_dn(self, user_dn, password):
		"""
		Creates a new user object with a password and enables the user so it can be used immediately.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:param password: The password of the user
		:type password: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: tuple

		"""
		try:
			sn = user_dn.split(',')[0][3:]
			domain = self._tree[3:].replace(',DC=','.')
			attributes = {
				'objectClass':  ['organizationalPerson', 'person', 'top', 'user'], 
				'sn': sn, 
				'sAMAccountName': sn,
				'displayName': sn,
				'userPrincipalName' : "{}@{}".format(sn, domain),
			}
			
			_, err = await self._con.add(user_dn, attributes)
			if err is not None:
				return False, err

			_, err = await self.change_password(user_dn, password)
			if err is not None:
				return False, err

			_, err = await self.enable_user(user_dn)
			if err is not None:
				return False, err

			return True, None
		except Exception as e:
			return False, e


	async def unlock_user(self, user_dn):
		"""
		Unlocks the user by clearing the lockoutTime attribute.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: tuple

		"""
		changes = {
			'lockoutTime': [('replace', [0])]
		}
		return await self._con.modify(user_dn, changes)

	async def enable_user(self, user_dn):
		"""
		Sets the user object to enabled by modifying the UserAccountControl attribute.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: tuple

		"""
		changes = {
			'userAccountControl': [('replace', [512])]
		}
		return await self._con.modify(user_dn, changes)
	
	async def disable_user(self, user_dn):
		"""
		Sets the user object to disabled by modifying the UserAccountControl attribute.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: tuple

		"""
		changes = {
			'userAccountControl': [('replace', [2])]
		}
		return await self._con.modify(user_dn, changes)

	async def add_user_spn(self, user_dn, spn):
		"""
		Adds an SPN record to the user object.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:param spn: The SPN to be added. It must follow the SPN string format specifications.
		:type spn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: tuple

		"""
		changes = {
			'servicePrincipalName': [('add', [spn])]
		}
		return await self._con.modify(user_dn, changes)

	async def add_additional_hostname(self, user_dn, hostname):
		"""
		Adds additional hostname to the user object.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: tuple

		"""
		changes = {
			'msds-additionaldnshostname': [('add', [hostname])]
		}
		return await self._con.modify(user_dn, changes)
		
	
	async def delete_user(self, user_dn):
		"""
		Deletes the user.
		This action is destructive!
		
		:param user_dn: The user's DN
		:type user_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: tuple

		"""
		return await self._con.delete(user_dn)

	async def change_password(self, user_dn: str, newpass: str, oldpass = None):
		"""
		Changes the password of a user.  
		If used with a high-privileged account (eg. Domain admin, Account operator...), the old password can be `None` 
		
		:param user_dn: The user's DN
		:type user_dn: str
		:param newpass: The new password
		:type newpass: str		
		:param oldpass: The current password
		:type oldpass: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: tuple

		"""
		changes = {
			'unicodePwd': []
		}
		if oldpass is not None:
			changes['unicodePwd'].append(('delete', ['"%s"' % oldpass]))
			changes['unicodePwd'].append(('add', ['"%s"' % newpass]))
		else:
			#if you are admin...
			changes['unicodePwd'].append(('replace', ['"%s"' % newpass]))

		return await self._con.modify(user_dn, changes)

	
	async def add_user_to_group(self, user_dn: str, group_dn: str):
		"""
		Adds a user to a group

		:param user_dn: The user's DN
		:type user_dn: str
		:param group_dn: The groups's DN
		:type group_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: tuple


		"""
		changes = {
			'member': [('add', [user_dn])]
		}
		return await self._con.modify(group_dn, changes)

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



	#async def get_permissions_for_dn(self, dn):
	#	"""
	#	Lists all users who can modify the specified dn
	#	"""
	#	async for secinfo in self.get_objectacl_by_dn(dn):
	#		for sdec in secinfo.nTSecurityDescriptor:
	#			sids_to_lookup = {}
	#			if not sdec.Dacl:
	#				continue
	#			
	#			for ace in sdec.Dacl.aces:
	#				sids_to_lookup[str(ace.Sid)] = 1
	#			
	#			for sid in sids_to_lookup:
	#				sids_to_lookup[sid] = self.get_dn_for_objectsid(sid)
	#				
	#			print(sids_to_lookup)
	#			
	#			for ace in sdec.Dacl.aces:
	#				if not sids_to_lookup[str(ace.Sid)]:
	#					print(str(ace.Sid))
	#				#print('===== %s =====' % sids_to_lookup[str(ace.Sid)])
	#				#if 
	#				#print(str(ace))
	
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


	#async def get_netdomain(self):
	#	def nameconvert(x):
	#		return x.split(',CN=')[1]
	#	"""
	#	gets the name of the current user's domain
	#	"""
	#	if not self._ldapinfo:
	#		self.get_ad_info()
	#	print(self._ldapinfo)
	#	dname = self._ldapinfo.distinguishedName.replace('DC','').replace('=','').replace(',','.')
	#	domain_controllers = ','.join(nameconvert(x) + '.' +dname  for x in self._ldapinfo.masteredBy)
	#	
	#	ridroleowner = nameconvert(self.get_ridroleowner()) + '.' +dname
	#	infraowner = nameconvert(self.get_infrastructureowner()) + '.' +dname
	#	pdcroleowner = nameconvert(self.get_pdcroleowner()) + '.' +dname
	#	
	#	print('name : %s' % dname)
	#	print('Domain Controllers : %s' % domain_controllers)
	#	print('DomainModeLevel : %s' % self._ldapinfo.domainmodelevel)
	#	print('PdcRoleOwner : %s' % pdcroleowner)
	#	print('RidRoleOwner : %s' % ridroleowner)
	#	print('InfrastructureRoleOwner : %s' % infraowner)
	#	
	#async def get_domaincontroller(self):
	#	ldap_filter = r'(userAccountControl:1.2.840.113556.1.4.803:=8192)'
	#	async for entry in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
	#		print('Forest: %s' % '')
	#		print('Name: %s' % entry['attributes'].get('dNSHostName'))
	#		print('OSVersion: %s' % entry['attributes'].get('operatingSystem'))
	#		print(entry['attributes'])

	#async def get_pdcroleowner(self):
	#	#http://adcoding.com/how-to-determine-the-fsmo-role-holder-fsmoroleowner-attribute/
	#	#get adinfo -> get ridmanagerreference attr -> look up the dn of ridmanagerreference -> get fsmoroleowner attr (which is a DN)
	#	if not self._ldapinfo:
	#		self.get_ad_info()
	#	
	#	ldap_filter = r'(distinguishedName=%s)' % self._ldapinfo.rIDManagerReference
	#	async for entry in self.pagedsearch(ldap_filter, ['fSMORoleOwner']):
	#		return entry['attributes']['fSMORoleOwner']
	#	
	#async def get_infrastructureowner(self):
	#	#http://adcoding.com/how-to-determine-the-fsmo-role-holder-fsmoroleowner-attribute/
	#	#"CN=Infrastructure,DC=concorp,DC=contoso,DC=com" -l fSMORoleOwner
	#	if not self._ldapinfo:
	#		self.get_ad_info()
	#	
	#	ldap_filter = r'(distinguishedName=%s)' % ('CN=Infrastructure,' + self._ldapinfo.distinguishedName)
	#	async for entry in self.pagedsearch(ldap_filter, ['fSMORoleOwner']):
	#		return entry['attributes']['fSMORoleOwner']
	#		
	#async def get_ridroleowner(self):
	#	#http://adcoding.com/how-to-determine-the-fsmo-role-holder-fsmoroleowner-attribute/
	#	if not self._ldapinfo:
	#		self.get_ad_info()
	#	
	#	ldap_filter = r'(distinguishedName=%s)' % ('CN=RID Manager$,CN=System,' + self._ldapinfo.distinguishedName)
	#	async for entry in self.pagedsearch(ldap_filter, ['fSMORoleOwner']):
	#		return entry['attributes']['fSMORoleOwner']

	#async def get_all_user_raw(self):
	#	"""
	#	Fetches all user objects from the AD, and returns MSADUser object
	#	"""
	#	logger.debug('Polling AD for all user objects')
	#	ldap_filter = r'(sAMAccountType=805306368)'
	#
	#	return self.pagedsearch(ldap_filter, MSADUser_ATTRS)