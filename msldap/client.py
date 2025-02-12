#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import copy
import asyncio
import string
import random
from typing import List, Dict, Tuple

from msldap import logger
from msldap.commons.common import MSLDAPClientStatus
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest, SDFlagsRequestValue
from msldap.protocol.constants import BASE, ALL_ATTRIBUTES, LEVEL

from msldap.protocol.query import escape_filter_chars
from msldap.connection import MSLDAPClientConnection
from msldap.protocol.messages import Control
from msldap.ldap_objects import *
from msldap.commons.utils import KNOWN_SIDS
from msldap.commons.target import MSLDAPTarget
from msldap.wintypes.dnsp.strcutures import DNS_RECORD
from msldap.commons.exceptions import LDAPSearchException
from asyauth.common.credentials import UniCredential

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.ace import ACCESS_ALLOWED_OBJECT_ACE, ADS_ACCESS_MASK
from winacl.dtyp.sid import SID
from winacl.dtyp.guid import GUID

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
	def __init__(self, target:MSLDAPTarget, creds:UniCredential, connection = None, keepalive = False):
		self.creds = creds
		self.target = target
		self.keepalive = keepalive
		self.ldap_query_page_size = 1000
		self._disable_channel_binding = False
		self._disable_signing = False
		self._null_channel_binding = False
		if self.target is not None:
			self.ldap_query_page_size = self.target.ldap_query_page_size
		
		self.ldap_query_ratelimit = 0
		if self.target is not None:
			self.ldap_query_ratelimit = self.target.ldap_query_ratelimit

		self._tree = None
		self._ldapinfo = None
		self._con = connection
		self.__keepalive_task = None
		self.keepalive_period = 10
		self.disconnected_evt = None
		self._sid_cache = {} #SID -> (domain, user)
		self._domainsid_cache = {} # SID -> domain
		
	
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await asyncio.wait_for(self.disconnect(), timeout = 1)
	
	async def __keepalive(self, temptree):
		try:
			while not self.disconnected_evt.is_set():
				if self._con is not None:
					ldap_filter = r'(distinguishedName=%s)' % temptree
					async for entry, err in self.pagedsearch(ldap_filter, MSADInfo_ATTRS):
						if err is not None:
							return None, err
				await asyncio.sleep(self.keepalive_period)

		
		except asyncio.CancelledError:
			return

		except Exception as e:
			print('Keepalive exception: %s' % e)
			await self.disconnect()
	
	async def disconnect(self):
		try:
			if self.__keepalive_task is not None:
				self.__keepalive_task.cancel()
			if self._con is not None:
				await self._con.disconnect()
			
			self.disconnected_evt.set()
		
		except Exception as e:
			return False, e

	async def connect(self):
		try:
			self.disconnected_evt = asyncio.Event()
			if self._con is None:
				self._con = MSLDAPClientConnection(self.target, self.creds)
				self._con._disable_channel_binding = self._disable_channel_binding
				self._con._disable_signing = self._disable_signing
				self._con._null_channel_binding = self._null_channel_binding
				_, err = await self._con.connect()
				if err is not None:
					raise err
				if self._con.is_anon is False:
					res, err = await self._con.bind()
					if err is not None:
						return False, err
				else:
					logger.debug('Skipping bind for no auth!')
			res, err = await self._con.get_serverinfo()
			if err is not None:
				raise err
			if res is None:
				print('RootDSE is empty! You will need to find the tree manually!')
			else:
				self._serverinfo = res
				self._tree = res['defaultNamingContext']
				self._ldapinfo, err = await self.get_ad_info()
				if self._con.is_anon is False:
					if err is not None:
						raise err
					self._domainsid_cache[self._ldapinfo.objectSid] = self._ldapinfo.name
			
				if self.keepalive is True:
					self.__keepalive_task = asyncio.create_task(self.__keepalive(res['defaultNamingContext']))
			return True, None
		except Exception as e:
			return False, e

	def get_server_info(self):
		return self._serverinfo
	
	async def get_domain_name(self):
		self._ldapinfo, err = await self.get_ad_info()
		if err is not None:
			return None, err
		domain = self._ldapinfo.name
		return domain, err
		

	async def pagedsearch(self, query:str, attributes:List[str], controls:List[Tuple[str, str, str]] = None, tree:str = None, search_scope:int=2):
		"""
		Performs a paged search on the AD, using the filter and attributes as a normal query does.
			!The LDAP connection MUST be active before invoking this function!

		:param query: LDAP query filter
		:type query: str
		:param attributes: List of requested attributes
		:type attributes: List[str]
		:param controls: additional controls to be passed in the query
		:type controls: dict
		:param tree: Base tree to perform the search on
		:type tree: str
		:param search_scope: LDAP search scope
		:type search_scope: int

		:return: Async generator which yields (`dict`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`dict`, :class:`Exception`)]

		"""
		logger.debug('Paged search, filter: %s attributes: %s' % (query, ','.join(attributes)))
		if self._con.status != MSLDAPClientStatus.RUNNING:
			if self._con.status == MSLDAPClientStatus.ERROR:
				print('There was an error in the connection!')
				return

		if tree is None:
			tree = self._tree
		if tree is None:
			raise Exception('BIND first!')
		t = []
		for x in attributes:
			t.append(x.encode())
		attributes = t

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
			tree, 
			query, 
			attributes = attributes, 
			size_limit = self.ldap_query_page_size, 
			controls = controls,
			rate_limit=self.ldap_query_ratelimit,
			search_scope=search_scope
			):
				
				if err is not None:
					yield None, err
					return
				if entry['objectName'] == '' and entry['attributes'] == '':
					#searchresref...
					continue
				#print('et %s ' % entry)
				yield entry, None

	async def get_tree_plot(self, root_dn:str, level:int = 2):
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
			root_dn, 
			'(distinguishedName=*)', 
			attributes = [b'distinguishedName'], 
			size_limit = self.ldap_query_page_size, 
			search_scope=LEVEL, 
			controls = None, 
			rate_limit=self.ldap_query_ratelimit
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

	async def get_all_users(self, attrs:List[str] = MSADUser_ATTRS):
		"""
		Fetches all user objects available in the LDAP tree and yields them as MSADUser object.
		
		:return: Async generator which yields (`MSADUser`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADUser`, :class:`Exception`)]
		
		"""
		logger.debug('Polling AD for all user objects')
		ldap_filter = r'(sAMAccountType=805306368)'
		async for entry, err in self.pagedsearch(ldap_filter, attrs):
			if err is not None:
				yield None, err
				return
			yield MSADUser.from_ldap(entry, self._ldapinfo), None
		logger.debug('Finished polling for entries!')

	async def get_all_machines(self, attrs:List[str] = MSADMachine_ATTRS):
		"""
		Fetches all machine objects available in the LDAP tree and yields them as MSADMachine object.

		:param attrs: Lists of attributes to request (eg. `['sAMAccountName', 'dNSHostName']`) Default: all attrs.
		:type attrs: list
		:return: Async generator which yields (`MSADMachine`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADMachine`, :class:`Exception`)]
		
		"""
		logger.debug('Polling AD for all user objects')
		ldap_filter = r'(sAMAccountType=805306369)'

		async for entry, err in self.pagedsearch(ldap_filter, attrs):
			if err is not None:
				yield None, err
				return
			yield MSADMachine.from_ldap(entry, self._ldapinfo), None
		logger.debug('Finished polling for entries!')
	
	async def get_all_gpos(self, attrs:List[str] = MSADGPO_ATTRS):
		"""
		Fetches all GPOs available in the LDAP tree and yields them as MSADGPO object.
		
		:return: Async generator which yields (`MSADGPO`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADGPO`, :class:`Exception`)]
		
		"""

		ldap_filter = r'(objectCategory=groupPolicyContainer)'
		async for entry, err in self.pagedsearch(ldap_filter, attrs):
			if err is not None:
				yield None, err
				return
			yield MSADGPO.from_ldap(entry), None
	
	async def get_all_containers(self, attrs:List[str] = MSADContainer_ATTRS):
		"""
		Fetches all container objects available in the LDAP tree and yields them as MSADContainer object.
		
		:return: Async generator which yields (`MSADUser`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADUser`, :class:`Exception`)]
		
		"""
		logger.debug('Polling AD for all container objects')
		ldap_filter = r'(&(objectCategory=container)(objectClass=container))'
		async for entry, err in self.pagedsearch(ldap_filter, attrs):
			if err is not None:
				yield None, err
				return
			yield MSADContainer.from_ldap(entry), None #self._ldapinfo
		logger.debug('Finished polling for entries!')
	
	async def get_all_foreignsecurityprincipals(self, attrs:List[str]):
		ldap_filter = r'(&(objectClass=foreignSecurityPrincipal)(objectCategory=foreignSecurityPrincipal))'
		async for entry, err in self.pagedsearch(ldap_filter, attrs):
			if err is not None:
				yield None, err
				return
			yield entry, None

	async def get_all_laps(self):
		"""
		Fetches all LAPS passwords for all machines. This functionality is only available to specific high-privileged users.

		:return: Async generator which yields (`dict`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`dict`, :class:`Exception`)]
		"""

		ldap_filter = r'(sAMAccountType=805306369)'
		attributes = ['cn','ms-mcs-AdmPwd']
		async for entry, err in self.pagedsearch(ldap_filter, attributes):
			yield entry, err
	
	async def get_all_laps_windows(self):
		"""
		Fetches all LAPS passwords for all machines. This functionality is only available to specific high-privileged users.

		:return: Async generator which yields (`dict`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`dict`, :class:`Exception`)]
		"""

		ldap_filter = r'(sAMAccountType=805306369)'
		# first try to get the plaintext password (the new windows laps doesn't necessary encrypt the PWs)
		attributes = ['cn','msLAPS-Password']
		async for entry, err in self.pagedsearch(ldap_filter, attributes):
			yield entry, err

		# now try to get the encrypted password
		attributes = ['cn','msLAPS-EncryptedPassword']
		async for entry, err in self.pagedsearch(ldap_filter, attributes):
			yield entry, err
		
		# now try to get the encrypted password history
		attributes = ['cn','msLAPS-EncryptedPasswordHistory']
		async for entry, err in self.pagedsearch(ldap_filter, attributes):
			yield entry, err
		
		# now try to get the encrypted DSRM password
		attributes = ['cn','msLAPS-EncryptedDSRMPassword']
		async for entry, err in self.pagedsearch(ldap_filter, attributes):
			yield entry, err
		
		# now try to get the encrypted DSRM password history
		attributes = ['cn','msLAPS-EncryptedDSRMPasswordHistory']
		async for entry, err in self.pagedsearch(ldap_filter, attributes):
			yield entry, err

	async def get_schemaentry(self, dn:str):
		"""
		Fetches one Schema entriy identified by dn

		:return: (`MSADSchemaEntry`, None) tuple on success or (None, `Exception`) on error
		:rtype: (:class:`MSADSchemaEntry`, :class:`Exception`)
		"""
		logger.debug('Polling Schema entry for %s'% dn)
		
		async for entry, err in self._con.pagedsearch(
			dn, 
			r'(distinguishedName=%s)' % escape_filter_chars(dn),
			attributes = [x.encode() for x in MSADSCHEMAENTRY_ATTRS], 
			size_limit = self.ldap_query_page_size, 
			search_scope=BASE, 
			controls = None, 
			):
				if err is not None:
					raise err
		
				return MSADSchemaEntry.from_ldap(entry), None
		else:
			return None, None
		logger.debug('Finished polling for entries!')
	
	async def get_all_schemaentry(self, attrs:List[str] = MSADSCHEMAENTRY_ATTRS):
		"""
		Fetches all Schema entries under CN=Schema,CN=Configuration,...

		:return: Async generator which yields (`MSADSchemaEntry`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADSchemaEntry`, :class:`Exception`)]
		"""
		res = await self.get_tree_plot(self._serverinfo['schemaNamingContext'], level = 1)		
		for x in res:
			for dn in res[x]:
				async for entry, err in self._con.pagedsearch(
					dn, 
					r'(distinguishedName=%s)' % escape_filter_chars(dn),
					attributes = [x.encode() for x in attrs], 
					size_limit = self.ldap_query_page_size, 
					search_scope=BASE, 
					controls = None,
					rate_limit=self.ldap_query_ratelimit
					):
						if err is not None:
							yield None, err
							return
									
						yield MSADSchemaEntry.from_ldap(entry), None
						break
				else:
					yield None, None
					
		logger.debug('Finished polling for entries!')

	async def get_laps(self, sAMAccountName:str):
		"""
		Fetches the LAPS password for a machine. This functionality is only available to specific high-privileged users.
		
		:param sAMAccountName: The username of the machine (eg. `COMP123$`).
		:type sAMAccountName: str
		:return: Laps attributes as a `dict`
		:rtype: (:class:`dict`, :class:`Exception`)
		"""

		ldap_filter = r'(&(sAMAccountType=805306369)(sAMAccountName=%s))' % sAMAccountName
		attributes = ['cn','ms-mcs-AdmPwd']
		async for entry, err in self.pagedsearch(ldap_filter, attributes):
			return entry, err

	async def get_user(self, sAMAccountName:str):
		"""
		Fetches one user object from the AD, based on the sAMAccountName attribute (read: username) 
		
		:param sAMAccountName: The username of the user.
		:type sAMAccountName: str
		:return: A tuple with the user as `MSADUser` and an `Exception` is there was any
		:rtype: (:class:`MSADUser`, :class:`Exception`)
		"""
		logger.debug('Polling AD for user %s'% sAMAccountName)
		ldap_filter = r'(&(objectClass=user)(sAMAccountName=%s))' % sAMAccountName
		async for entry, err in self.pagedsearch(ldap_filter, MSADUser_ATTRS):
			if err is not None:
				return None, err
			return MSADUser.from_ldap(entry, self._ldapinfo), None
		else:
			return None, None
		logger.debug('Finished polling for entries!')

	async def get_machine(self, sAMAccountName:str):
		"""
		Fetches one machine object from the AD, based on the sAMAccountName attribute (read: username) 
		
		:param sAMAccountName: The username of the machine.
		:type sAMAccountName: str
		:return: A tuple with the user as `MSADMachine` and an `Exception` is there was any
		:rtype: (:class:`MSADMachine`, :class:`Exception`)
		"""
		logger.debug('Polling AD for user %s'% sAMAccountName)
		ldap_filter = r'(&(sAMAccountType=805306369)(sAMAccountName=%s))' % sAMAccountName
		async for entry, err in self.pagedsearch(ldap_filter, MSADMachine_ATTRS):
			if err is not None:
				return None, err
			return MSADMachine.from_ldap(entry, self._ldapinfo), None
		else:
			return None, None
		logger.debug('Finished polling for entries!')

	async def get_ad_info(self):
		"""
		Polls for basic AD information (needed for determine password usage characteristics!)
		
		:return: A tuple with the domain information as `MSADInfo` and an `Exception` is there was any
		:rtype: (:class:`MSADInfo`, :class:`Exception`)
		"""
		logger.debug('Polling AD for basic info')
		ldap_filter = r'(distinguishedName=%s)' % self._tree
		async for entry, err in self.pagedsearch(ldap_filter, MSADInfo_ATTRS):
			if err is not None:
				return None, err
			self._ldapinfo = MSADInfo.from_ldap(entry)
			return self._ldapinfo, None

		logger.debug('Poll finished!')

	async def get_all_spn_entries(self):
		"""
		Fetches all service user objects from the AD, and returns MSADUser object.
		Service user refers to an user with SPN (servicePrincipalName) attribute set

		:param include_machine: Specifies wether machine accounts should be included in the query
		:type include_machine: bool
		:return: Async generator which yields tuples with a string in SPN format and an Exception if there was any
		:rtype: Iterator[(:class:`str`, :class:`Exception`)]
		
		"""

		logger.debug('Polling AD for all SPN entries')
		ldap_filter = r'(&(sAMAccountType=805306369))'
		attributes = ['objectSid','sAMAccountName', 'servicePrincipalName']

		async for entry, err in self.pagedsearch(ldap_filter, attributes):
			yield entry, err

	async def get_all_service_users(self, include_machine:bool = False):
		"""
		Fetches all service user objects from the AD, and returns MSADUser object.
		Service user refers to an user with SPN (servicePrincipalName) attribute set

		:param include_machine: Specifies wether machine accounts should be included in the query
		:type include_machine: bool
		
		:return: Async generator which yields (`MSADUser`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADUser`, :class:`Exception`)]

		"""
		logger.debug('Polling AD for all user objects, machine accounts included: %s'% include_machine)
		if include_machine == True:
			ldap_filter = r'(servicePrincipalName=*)'
		else:
			ldap_filter = r'(&(servicePrincipalName=*)(!(sAMAccountName=*$)))'

		async for entry, err in self.pagedsearch(ldap_filter, MSADUser_ATTRS):
			if err is not None:
				yield None, err
				return
			yield MSADUser.from_ldap(entry, self._ldapinfo), None
		logger.debug('Finished polling for entries!')

	async def get_all_knoreq_users(self, include_machine:bool = False):
		"""
		Fetches all user objects with useraccountcontrol DONT_REQ_PREAUTH flag set from the AD, and returns MSADUser object.
		
		:param include_machine: Specifies wether machine accounts should be included in the query
		:type include_machine: bool
		:return: Async generator which yields (`MSADUser`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADUser`, :class:`Exception`)]

		"""
		logger.debug('Polling AD for all user objects, machine accounts included: %s'% include_machine)
		if include_machine == True:
			ldap_filter = r'(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
		else:
			ldap_filter = r'(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(sAMAccountName=*$)))'

		async for entry, err in self.pagedsearch(ldap_filter, MSADUser_ATTRS):
			if err is not None:
				yield None, err
				return
			yield MSADUser.from_ldap(entry, self._ldapinfo), None
		logger.debug('Finished polling for entries!')
			
	async def get_objectacl_by_dn_p(self, dn:str, flags:SDFlagsRequest = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION):
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
		
		async for entry, err in self.pagedsearch(ldap_filter, attributes, controls = controls):
			if err is not None:
				yield None, err
				return
			yield MSADSecurityInfo.from_ldap(entry), None

	async def get_objectacl_by_dn(self, dn:str, flags:SDFlagsRequest = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION):
		"""
		Returns the full or partial Security Descriptor of the object specified by it's DN.
		The flags indicate which part of the security Descriptor to be returned.
		By default the full SD info is returned.

		:param object_dn: The object's DN
		:type object_dn: str
		:param flags: Flags indicate the data type to be returned.
		:type flags: :class:`SDFlagsRequest`
		:return: nTSecurityDescriptor attribute of the object as `bytes` and an `Exception` is there was any
		:rtype: (:class:`bytes`, :class:`Exception`)

		"""
		
		req_flags = SDFlagsRequestValue({'Flags' : flags})
		
		ldap_filter = r'(distinguishedName=%s)' % escape_filter_chars(dn)
		attributes = ['nTSecurityDescriptor']
		controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]
		
		async for entry, err in self.pagedsearch(ldap_filter, attributes, controls = controls):
			if err is not None:
				return None, err
			return entry['attributes'].get('nTSecurityDescriptor'), None
		return None, None

	async def set_objectacl_by_dn(self, object_dn:str, data:bytes, flags:SDFlagsRequest = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION):
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
		controls = [
					Control({
						'controlType' : b'1.2.840.113556.1.4.801',
						'controlValue': req_flags.dump(),
						'criticality' : True,
					})
				]

		changes = {
			'nTSecurityDescriptor': [('replace', data)]
		}
		return await self._con.modify(object_dn, changes, controls = controls)
		
	async def get_all_groups(self, attrs:List[str] = MSADGroup_ATTRS):
		"""
		Yields all Groups present in the LDAP tree.  
		
		:return: Async generator which yields (`MSADGroup`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADGroup`, :class:`Exception`)]
		"""
		ldap_filter = r'(objectClass=group)'
		async for entry, err in self.pagedsearch(ldap_filter, attrs):
			if err is not None:
				yield None, err
				return
			yield MSADGroup.from_ldap(entry), None
			
	async def get_all_ous(self, attrs:List[str] = MSADOU_ATTRS):
		"""
		Yields all OUs present in the LDAP tree.  

		:return: Async generator which yields (`MSADOU`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADOU`, :class:`Exception`)]
		"""
		ldap_filter = r'(objectClass=organizationalUnit)'
		async for entry, err in self.pagedsearch(ldap_filter, attrs):
			if err is not None:
				yield None, err
				return
			yield MSADOU.from_ldap(entry), None
			
	async def get_group_by_dn(self, group_dn:str):
		"""
		Returns an `MSADGroup` object for the group specified by group_dn

		:param group_dn: The user's DN
		:type group_dn: str
		:return: tuple of `MSADGroup` and an `Exception` is there was any
		:rtype: (:class:`MSADGroup`, :class:`Exception`)
		"""

		ldap_filter = r'(&(objectClass=group)(distinguishedName=%s))' % escape_filter_chars(group_dn)
		async for entry, err in self.pagedsearch(ldap_filter, MSADGroup_ATTRS):
			if err is not None:
				return None, err
			return MSADGroup.from_ldap(entry), None
		
		return None, Exception('Search returned no results!')
			
	async def get_user_by_dn(self, user_dn:str):
		"""
		Fetches the DN for an object specified by `user_dn`

		:param user_dn: The user's DN
		:type user_dn: str
		:return: The user object
		:rtype: (:class:`MSADUser`, :class:`Exception`)
		"""

		ldap_filter = r'(&(objectClass=user)(distinguishedName=%s))' % user_dn
		async for entry, err in self.pagedsearch(ldap_filter, MSADUser_ATTRS):
			if err is not None:
				return None, err
			return MSADUser.from_ldap(entry), None
			
	async def get_group_members(self, dn:str, recursive:bool = False):
		"""
		Fetches the DN for an object specified by `objectsid`

		:param dn: The object's DN
		:type dn: str
		:param recursive: Indicates wether the lookup should recursively affect all groups
		:type recursive: bool
		:return: Async generator which yields (`MSADUser`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADUser`, :class:`Exception`)]
		"""

		group, err = await self.get_group_by_dn(dn)
		if err is not None:
			yield None, err
			return
		if group.member:
			for member in group.member:
				async for result, err in self.get_object_by_dn(member):
					if isinstance(result, MSADGroup) and recursive:
						async for user, err in self.get_group_members(result.distinguishedName, recursive = True):
							yield user, err
					else:
						yield result, err
		
						
	async def get_dn_for_objectsid(self, objectsid:str):
		"""
		Fetches the DN for an object specified by `objectsid`

		:param objectsid: The object's SID
		:type objectsid: str
		:return: The distinguishedName
		:rtype: (:class:`str`, :class:`Exception`)

		"""

		ldap_filter = r'(objectSid=%s)' % str(objectsid)
		async for entry, err in self.pagedsearch(ldap_filter, ['distinguishedName']):
			if err is not None:
				return None, err
			
			return entry['attributes']['distinguishedName'], None
		
		return None, Exception('Search returned no results!')

	async def get_objectsid_for_dn(self, dn:str):
		"""
		Fetches the objectsid for an object specified by `dn`

		:param dn: The object's distinguishedName
		:type dn: str
		:return: The SID of the pobject
		:rtype: (:class:`str`, :class:`Exception`)

		"""

		ldap_filter = r'(distinguishedName=%s)' % escape_filter_chars(dn)
		async for entry, err in self.pagedsearch(ldap_filter, ['objectSid']):
			if err is not None:
				return None, err
			
			return entry['attributes']['objectSid'], None
		
		return None, Exception('Search returned no results!')
	
	async def get_tokengroups_user(self, samaccountname:str):
		ldap_filter = r'(sAMAccountName=%s)' % escape_filter_chars(samaccountname)
		user_dn = None
		async for entry, err in self.pagedsearch(ldap_filter, ['distinguishedName']):
			if err is not None:
				return None, err
			
			user_dn = entry['attributes']['distinguishedName']
		
		if user_dn is None:
			return None, Exception('User not found! %s' % samaccountname)

		tokengroup = []
		async for sids, err in self.get_tokengroups(user_dn):
			if err is not None:
				return None, err
			tokengroup.append(sids)
		
		return tokengroup, None
		
	async def get_tokengroups(self, dn:str):
		"""
		Yields SIDs of groups that the given DN is a member of.

		:return: Async generator which yields (`str`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`str`, :class:`Exception`)]

		"""
		ldap_filter = r'(distinguishedName=%s)' % escape_filter_chars(dn)
		attributes=[b'tokenGroups']

		async for entry, err in self._con.pagedsearch(
			dn, 
			ldap_filter, 
			attributes = attributes, 
			size_limit = self.ldap_query_page_size, 
			search_scope=BASE, 
			rate_limit=self.ldap_query_ratelimit
			):
				if err is not None:
					yield None, err
					return
				
				#print(entry['attributes'])
				if 'tokenGroups' in entry['attributes']:
					for sid_data in entry['attributes']['tokenGroups']:
						yield sid_data, None
			
	async def get_all_tokengroups(self):
		"""
		Yields all effective group membership information for all objects of the following type:
		Users, Groups, Computers

		:return: Async generator which yields (`dict`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`dict`, :class:`Exception`)]

		"""

		ldap_filter = r'(|(sAMAccountType=805306369)(objectClass=group)(sAMAccountType=805306368))'
		async for entry, err in self.pagedsearch(
			ldap_filter, 
			attributes = ['dn', 'cn', 'objectSid','objectClass', 'objectGUID']
			):				
				if err is not None:
					yield None, err
					return
				if 'objectName' in entry:
					#print(entry['objectName'])
					async for entry2, err in self._con.pagedsearch(
						entry['objectName'], 
						r'(distinguishedName=%s)' % escape_filter_chars(entry['objectName']), 
						attributes = [b'tokenGroups'], 
						size_limit = self.ldap_query_page_size, 
						search_scope=BASE, 
						rate_limit=self.ldap_query_ratelimit
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

									}, None

	async def get_all_objectacl(self):
		"""
		Yields the security descriptor of all objects in the LDAP tree of the following types:  
		Users, Computers, GPOs, OUs, Groups

		:return: Async generator which yields (`MSADSecurityInfo`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADSecurityInfo`, :class:`Exception`)]

		"""
		
		flags_value = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION
		req_flags = SDFlagsRequestValue({'Flags' : flags_value})
		
		ldap_filter = r'(|(objectClass=organizationalUnit)(objectCategory=groupPolicyContainer)(sAMAccountType=805306369)(objectClass=group)(sAMAccountType=805306368))'
		async for entry, err in self.pagedsearch(ldap_filter, attributes = ['dn']):
			if err is not None:
				yield None, err
				return
			ldap_filter = r'(distinguishedName=%s)' % escape_filter_chars(entry['objectName'])
			attributes = MSADSecurityInfo.ATTRS
			controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]
			
			async for entry2, err in self.pagedsearch(ldap_filter, attributes, controls = controls):
				if err is not None:
					yield None, err
					return
				yield MSADSecurityInfo.from_ldap(entry2), None


	async def get_all_trusts(self, attrs:List[str] = MSADDomainTrust_ATTRS):
		"""
		Yields all trusted domains.

		:return: Async generator which yields (`MSADDomainTrust`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`MSADDomainTrust`, :class:`Exception`)]

		"""

		ldap_filter = r'(objectClass=trustedDomain)'
		async for entry, err in self.pagedsearch(ldap_filter, attributes = attrs):
			if err is not None:
				yield None, err
				return
			yield MSADDomainTrust.from_ldap(entry), None
		
	async def create_user_dn(self, user_dn:str, password:str):
		"""
		Creates a new user object with a password and enables the user so it can be used immediately.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:param password: The password of the user
		:type password: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)

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


	async def unlock_user(self, user_dn:str):
		"""
		Unlocks the user by clearing the lockoutTime attribute.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)

		"""
		changes = {
			'lockoutTime': [('replace', 0)]
		}
		return await self._con.modify(user_dn, changes)

	async def enable_user(self, user_dn:str):
		"""
		Sets the user object to enabled by modifying the UserAccountControl attribute.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)

		"""
		changes = {
			'userAccountControl': [('replace', 512)]
		}
		return await self._con.modify(user_dn, changes)
	
	async def disable_user(self, user_dn:str):
		"""
		Sets the user object to disabled by modifying the UserAccountControl attribute.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)

		"""
		changes = {
			'userAccountControl': [('replace', 2)]
		}
		return await self._con.modify(user_dn, changes)

	async def add_user_spn(self, user_dn:str, spn:str):
		"""
		Adds an SPN record to the user object.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:param spn: The SPN to be added. It must follow the SPN string format specifications.
		:type spn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)

		"""
		changes = {
			'servicePrincipalName': [('add', spn)]
		}
		return await self._con.modify(user_dn, changes)
	
	async def del_user_spn(self, user_dn:str, spn:str):
		"""
		Adds an SPN record to the user object.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:param spn: The SPN to be added. It must follow the SPN string format specifications.
		:type spn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)

		"""
		changes = {
			'servicePrincipalName': [('delete', spn)]
		}
		return await self._con.modify(user_dn, changes)

	async def add_additional_hostname(self, user_dn:str, hostname:str):
		"""
		Adds additional hostname to the user object.
		
		:param user_dn: The user's DN
		:type user_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)

		"""
		changes = {
			'msds-additionaldnshostname': [('add', hostname)]
		}
		return await self._con.modify(user_dn, changes)
		
	
	async def delete_user(self, user_dn:str):
		"""
		Deletes the user.
		This action is destructive!
		
		:param user_dn: The user's DN
		:type user_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)

		"""
		return await self._con.delete(user_dn)

	async def change_password(self, user_dn: str, newpass: str, oldpass:str = None):
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
		:rtype: (:class:`bool`, :class:`Exception`)

		"""
		changes = {
			'unicodePwd': []
		}
		if oldpass is not None:
			changes['unicodePwd'].append(('delete', '"%s"' % oldpass))
			changes['unicodePwd'].append(('add', '"%s"' % newpass))
		else:
			#if you are admin...
			changes['unicodePwd'].append(('replace', '"%s"' % newpass))

		return await self._con.modify(user_dn, changes)

	
	async def add_user_to_group(self, user_dn: str, group_dn: str):
		"""
		Adds a user to a group

		:param user_dn: The user's DN
		:type user_dn: str
		:param group_dn: The groups's DN
		:type group_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)


		"""
		changes = {
			'member': [('add', user_dn)]
		}
		return await self._con.modify(group_dn, changes)

	async def del_user_from_group(self, user_dn: str, group_dn: str):
		"""
		Removes user from group

		:param user_dn: The user's DN
		:type user_dn: str
		:param group_dn: The groups's DN
		:type group_dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)


		"""
		changes = {
			'member': [('delete', user_dn)]
		}
		return await self._con.modify(group_dn, changes)
		

	async def get_object_by_dn(self, dn:str, expected_class = None):
		ldap_filter = r'(distinguishedName=%s)' % escape_filter_chars(dn)
		async for entry, err in self.pagedsearch(ldap_filter, ALL_ATTRIBUTES):
			if err is not None:
				yield None, err
				return
			temp = entry['attributes'].get('objectClass')
			if expected_class:
				yield expected_class.from_ldap(entry), None
			
			if not temp:
				yield entry, None
			elif 'user' in temp:
				yield MSADUser.from_ldap(entry), None
			elif 'group' in temp:
				yield MSADGroup.from_ldap(entry), None

	async def modify(self, dn:str, changes:Dict[str, object], controls:Dict[str, object] = None):
		"""
		Performs the modify operation.
		
		:param dn: The DN of the object whose attributes are to be modified
		:type dn: str
		:param changes: Describes the changes to be made on the object. Must be a dictionary of the following format: {'attribute': [('change_type', [value])]}
		:type changes: dict
		:param controls: additional controls to be passed in the query
		:type controls: dict
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		if controls is None:
			controls = []
		controls_conv = []
		for control in controls:	
			controls_conv.append(Control(control))
		return await self._con.modify(dn, changes, controls=controls_conv)


	async def add(self, dn:str, attributes:Dict[str, object]):
		"""
		Performs the add operation.
		
		:param dn: The DN of the object to be added
		:type dn: str
		:param attributes: Attributes to be used in the operation
		:type attributes: dict
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		
		return await self._con.add(dn, attributes)

	async def delete(self, dn:str):
		"""
		Performs the delete operation.
		
		:param dn: The DN of the object to be deleted
		:type dn: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""

		return await self._con.delete(dn)

	async def add_priv_addmember(self, user_dn:str, group_dn:str):
		"""Adds AddMember rights to the user on the group specified by group_dn"""
		try:
			#getting SID of target dn
			user_sid, err = await self.get_objectsid_for_dn(user_dn)
			if err is not None:
				raise err
			
			res, err = await self.get_objectacl_by_dn(group_dn)
			if err is not None:
				raise err
			if res is None:
				raise Exception('Failed to get forest\'s SD')
			group_sd = SECURITY_DESCRIPTOR.from_bytes(res)

			new_sd = copy.deepcopy(group_sd)
			
			ace_1 = ACCESS_ALLOWED_OBJECT_ACE()
			ace_1.Sid = SID.from_string(user_sid)
			ace_1.ObjectType = GUID.from_string('bf9679c0-0de6-11d0-a285-00aa003049e2')
			ace_1.Mask = ADS_ACCESS_MASK.WRITE_PROP
			ace_1.AceFlags = 0

			new_sd.Dacl.aces.append(ace_1)

			changes = {
				'nTSecurityDescriptor' : [('replace', new_sd.to_bytes())]
			}
			req_flags = SDFlagsRequestValue({
				'Flags': SDFlagsRequest.DACL_SECURITY_INFORMATION
			})
			controls = [{
				'controlType': b'1.2.840.113556.1.4.801',
				'controlValue': req_flags.dump(),
				'criticality': False
			}]
			_, err = await self.modify(group_dn, changes, controls)
			if err is not None:
				raise err

			return True, None
		except Exception as e:
			return False, e

	async def add_priv_dcsync(self, user_dn:str, forest_dn:str = None):
		"""Adds DCSync rights to the given user by modifying the forest's Security Descriptor to add GetChanges and GetChangesAll ACE"""
		try:
			#getting SID of target dn
			user_sid, err = await self.get_objectsid_for_dn(user_dn)
			if err is not None:
				raise err
			
			if forest_dn is None:					
				forest_dn = self._ldapinfo.distinguishedName
			
			res, err = await self.get_objectacl_by_dn(forest_dn)
			if err is not None:
				raise err
			if res is None:
				raise Exception('Failed to get forest\'s SD')
			forest_sd = SECURITY_DESCRIPTOR.from_bytes(res)


			new_sd = copy.deepcopy(forest_sd)
			
			ace_1 = ACCESS_ALLOWED_OBJECT_ACE()
			ace_1.Sid = SID.from_string(user_sid)
			ace_1.ObjectType = GUID.from_string('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')
			ace_1.Mask = ADS_ACCESS_MASK.CONTROL_ACCESS
			ace_1.AceFlags = 0


			new_sd.Dacl.aces.append(ace_1)
			
			ace_2 = ACCESS_ALLOWED_OBJECT_ACE()
			ace_2.Sid = SID.from_string(user_sid)
			ace_2.ObjectType = GUID.from_string('1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
			ace_2.Mask = ADS_ACCESS_MASK.CONTROL_ACCESS
			ace_2.AceFlags = 0

			new_sd.Dacl.aces.append(ace_2)

			changes = {
				'nTSecurityDescriptor' : [('replace', new_sd.to_bytes())]
			}
			req_flags = SDFlagsRequestValue({
				'Flags': SDFlagsRequest.DACL_SECURITY_INFORMATION
			})
			controls = [{
				'controlType': b'1.2.840.113556.1.4.801',
				'controlValue': req_flags.dump(),
				'criticality': False
			}]
			_, err = await self.modify(forest_dn, changes, controls)
			if err is not None:
				raise err

			return True, None
		except Exception as e:
			return False, e

	async def change_priv_owner(self, new_owner_sid:str, target_dn:str, target_attribute = None):
		"""Changes the owner in a Security Descriptor to the new_owner_sid on an LDAP object or on an LDAP object's attribute identified by target_dn and target_attribute. target_attribute can be omitted to change the target_dn's SD's owner"""
		try:
			try:
				new_owner_sid = SID.from_string(new_owner_sid)
			except:
				return False, Exception('Incorrect SID')


			target_sd = None
			if target_attribute is None or target_attribute == '':
				target_attribute = 'nTSecurityDescriptor'
				res, err = await self.get_objectacl_by_dn(target_dn)
				if err is not None:
					raise err
				target_sd = SECURITY_DESCRIPTOR.from_bytes(res)
			else:
				query = '(distinguishedName=%s)' % target_dn
				async for entry, err in self.pagedsearch(query, [target_attribute]):
					if err is not None:
						raise err
					target_sd = SECURITY_DESCRIPTOR.from_bytes(entry['attributes'][target_attribute])
					break
				else:
					raise Exception('Target DN not found!')

			new_sd = copy.deepcopy(target_sd)
			new_sd.Owner = new_owner_sid

			changes = {
				target_attribute : [('replace', new_sd.to_bytes())]
			}
			_, err = await self.modify(target_dn, changes)
			if err is not None:
				raise err

			return True, None
		except Exception as e:
			return False, e

	async def list_root_cas(self):
		try:
			ldap_filter = "(objectClass=certificationAuthority)"
			tree = "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,%s" % self._ldapinfo.distinguishedName
			async for entry, err in self.pagedsearch(ldap_filter, attributes = MSADCA_ATTRS, tree = tree):
				if err is not None:
					yield None, err
					return
				yield MSADCA.from_ldap(entry, 'ROOTCA'), None

		except Exception as e:
			yield None, e
			return
	
	async def list_ntcas(self):
		try:
			ldap_filter = "(objectClass=certificationAuthority)"
			tree = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,%s" % self._ldapinfo.distinguishedName
			async for entry, err in self.pagedsearch(ldap_filter, attributes = MSADCA_ATTRS, tree = tree):
				if err is not None:
					yield None, err
					return
				yield MSADCA.from_ldap(entry, 'NTCA'), None

		except Exception as e:
			yield None, e
			return

	async def list_aiacas(self):
		try:
			ldap_filter = "(objectClass=certificationAuthority)"
			tree = "CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,%s" % self._ldapinfo.distinguishedName
			async for entry, err in self.pagedsearch(ldap_filter, attributes = MSADCA_ATTRS, tree = tree):
				if err is not None:
					yield None, err
					return
				yield MSADCA.from_ldap(entry, 'AIACA'), None

		except Exception as e:
			yield None, e
			return

	async def list_enrollment_services(self):
		try:
			ldap_filter = "(objectCategory=pKIEnrollmentService)"
			tree = "CN=Configuration,%s" % self._ldapinfo.distinguishedName

			async for entry, err in self.pagedsearch(ldap_filter, attributes = MSADEnrollmentService_ATTRS, tree = tree):
				if err is not None:
					yield None, err
					return
				yield MSADEnrollmentService.from_ldap(entry), None
			
		except Exception as e:
			yield None, e
			return

	async def list_certificate_templates(self, name:str = None):
		try:
			req_flags = SDFlagsRequestValue({'Flags' : SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION})
			controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]

			ldap_filter = "(objectCategory=pKICertificateTemplate)"
			if name is not None:
				ldap_filter = "(&(objectCategory=pKICertificateTemplate)(name=%s))" % name
			tree = "CN=Configuration,%s" % self._ldapinfo.distinguishedName

			async for entry, err in self.pagedsearch(ldap_filter, attributes = MSADCertificateTemplate_ATTRS, controls=controls, tree = tree):
				if err is not None:
					yield None, err
					return
				yield MSADCertificateTemplate.from_ldap(entry), None
			
		except Exception as e:
			yield None, e
			return

	async def list_gmsa(self):
		try:
			ldap_filter = r'(objectClass=msDS-GroupManagedServiceAccount)'
			async for entry, err in self.pagedsearch(ldap_filter, attributes = ['sAMAccountName','msDS-GroupMSAMembership', 'msDS-ManagedPassword']):
				if err is not None:
					yield None, None, None, err
					return
				yield entry['attributes'].get('sAMAccountName'), entry['attributes'].get('msDS-GroupMSAMembership'), entry['attributes'].get('msDS-ManagedPassword'), None

		except Exception as e:
			yield None, None, None, e
			return

	async def get_all_gmsa(self, attributes:list = MSADGMSAUser_ATTRS):
		try:
			ldap_filter = r'(objectClass=msDS-GroupManagedServiceAccount)'
			async for entry, err in self.pagedsearch(ldap_filter, attributes = ALL_ATTRIBUTES):
				if err is not None:
					yield None, err
					return
				gmsauser = MSADGMSAUser.from_ldap(entry)
				yield gmsauser, None

		except Exception as e:
			yield None, e
			return
		
	async def add_computer(self, computername:str = None, password:str = None):
		try:
			if computername is None:
				computername = 'COMP%s$' % ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4))
			if computername.endswith('$') is False:
				computername += '$'
			if password is None:
				password = ''.join(random.choice(string.ascii_uppercase + string.digits + '!@#$%+') for _ in range(16))
			
			
			# Create computer object
			domain = self._ldapinfo.distinguishedName.replace('DC','').replace('=','').replace(',','.')
			attributes = {
				'objectClass':  ['top', 'person', 'organizationalPerson', 'user', 'computer'], 
				#'cn': computername[:-1], 
				'sAMAccountName': computername,
				'name': computername[:-1],
				'servicePrincipalName' : "HOST/{}.{}".format(computername[:-1], domain),
			}
			dn = 'CN=%s,CN=Computers,%s' % (computername[:-1], self._ldapinfo.distinguishedName)
			_, err = await self.add(dn, attributes)
			if err is not None:
				raise err
			
			# enabling computer account
			changes = {
				'userAccountControl': [('replace', 4096)]
			}
			_, err = await self._con.modify(dn, changes)
			if err is not None:
				raise err
			
			# Change password
			_, err = await self.change_password(dn, password)
			if err is not None:
				raise err
			
			# Get computer object
			computer, err = await self.get_machine(computername)
			if err is not None:
				raise err
			

			return computer, password, None
		except Exception as e:
			return None, None, e
		
	async def change_samaccountname(self, dn:str, samaccountname:str):
		try:
			changes = {
				'sAMAccountName': [('replace', samaccountname)]
			}
			_, err = await self._con.modify(dn, changes)
			if err is not None:
				raise err
			return None
		except Exception as e:
			return e
		

	async def resolv_sd(self, sd:SECURITY_DESCRIPTOR or bytes):
		"Resolves all SIDs found in security descriptor, returns lookup table"
		try:
			if isinstance(sd, bytes):
				sd = SECURITY_DESCRIPTOR.from_bytes(sd)
			
			lookup_table = {}
			sids = {}
			sids[str(sd.Owner)] = 1
			sids[str(sd.Group)] = 1
			if sd.Dacl is not None:
				for ace in sd.Dacl.aces:
					sids[str(ace.Sid)] = 1
			if sd.Sacl is not None:
				for ace in sd.Sacl.aces:
					sids[str(ace.Sid)] = 1
			
			for sid in sids:
				domain, username, err = await self.resolv_sid(sid)
				if err is not None:
					raise err
				lookup_table[sid] = (domain, username)
			
			return lookup_table, None

		except Exception as e:
			return None, e
	
	async def resolv_sid(self, sid:SID or str, use_cache:bool = True):
		"""Performs a SID lookup for object and returns the domain name and the samaccountname"""
		try:
			sid = str(sid).upper()
			if sid in KNOWN_SIDS:
				return "BUILTIN", KNOWN_SIDS[sid], None
			domain = None
			username = None
			domainsid = sid.rsplit('-',1)[0]
			if domainsid not in self._domainsid_cache:
				logger.debug('Domain SID "%s" was not found! ' % domainsid)
				return '???', '???', None
			domain = self._domainsid_cache[domainsid]
			if sid in self._sid_cache:
				username = self._sid_cache[sid]
			
			else:
				ldap_filter = r'(objectSid=%s)' % sid
				async for entry, err in self.pagedsearch(ldap_filter, attributes = ['sAMAccountName']):
					if err is not None:
						return None, None, err
					username = entry['attributes'].get('sAMAccountName')
				
				if username is None:
					return domain, '???', None
					#raise Exception('User not found! %s' % sid)
			
			if use_cache is True:
				self._sid_cache[sid] = username
			return domain, username, None
		except Exception as e:
			return None, None, e
	
	async def whoami(self):
		return await self._con.whoami()

	async def whoamifull(self):
		"""Full whoami"""
		#TODO: it can be the case that the server returns the SID of the user
		# implement that path!
		result = {}
		try:
			res, err = await self.whoami()
			if err is not None:
				raise err
			result['raw'] = res
			result['tokengroups'] = []
			if res.startswith('u:') is True:
				domain, samaccountname = res[2:].split('\\', 1)
				result['domain'] = domain
				result['samaccountname'] = samaccountname
				user, err = await self.get_user(samaccountname)
				if err is not None:
					raise err
				result['sid'] = str(user.objectSid)
				result['tokengroups'].append(str(user.objectSid))
				result['groups'] = {}
				async for group_sid, err in self.get_tokengroups(user.distinguishedName):
					if err is not None:
						raise err
					result['tokengroups'].append(str(group_sid))
					result['groups'][group_sid] = ('NA','NA')
					domain, username, err = await self.resolv_sid(group_sid)
					if err is not None:
						raise err
					result['groups'][group_sid] = (domain, username)				
			
			return result, None
		except:
			return result, None

	async def get_unconstrained_machines(self):
		ldap_filter = r'(&(sAMAccountType=805306369)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(userAccountControl:1.2.840.113556.1.4.803:=524288))'
		async for entry, err in self.pagedsearch(ldap_filter, ['sAMAccountName']):
			if err is not None:
				yield None, err
				return
			yield entry.get('attributes', {}).get('sAMAccountName'), None
		logger.debug('Finished polling for entries!')
	
	async def get_unconstrained_users(self):
		ldap_filter = r'(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
		async for entry, err in self.pagedsearch(ldap_filter, ['sAMAccountName']):
			if err is not None:
				yield None, err
				return
			yield entry.get('attributes', {}).get('sAMAccountName'), None
		logger.debug('Finished polling for entries!')

	async def get_all_constrained(self):
		ldap_filter = r'(&(|(sAMAccountType=805306369)(sAMAccountType=805306368))(msDS-AllowedToDelegateTo=*))'
		async for entry, err in self.pagedsearch(ldap_filter, ['sAMAccountName', 'msDS-AllowedToDelegateTo']):
			if err is not None:
				yield None, err
				return
			yield entry.get('attributes', {}), None
		logger.debug('Finished polling for entries!')

	async def get_all_s4u2proxy(self):
		ldap_filter = r'(&(|(sAMAccountType=805306369)(sAMAccountType=805306368))(userAccountControl:1.2.840.113556.1.4.803:=16777216))'
		async for entry, err in self.pagedsearch(ldap_filter, ['sAMAccountName']):
			if err is not None:
				yield None, err
				return
			yield entry.get('attributes', {}).get('sAMAccountName'), None
		logger.debug('Finished polling for entries!')
	
	async def sam2dn(self, sAMAccountName):
		"""Fetches the DN of an object based on the sAMAccountName"""
		try:
			query = '(sAMAccountName=%s)' % sAMAccountName
			async for entry, err in self.pagedsearch(query, ['distinguishedName', 'objectSid']):
				if err is not None:
					raise err
				return entry['attributes']['distinguishedName'], None
		except Exception as e:
			return None, e
	
	async def sid2dn(self, sid):
		"""Fetches the DN of an object based on the objectSid"""
		try:
			query = '(objectSid=%s)' % sid
			async for entry, err in self.pagedsearch(query, ['distinguishedName']):
				if err is not None:
					raise err
				return entry['attributes']['distinguishedName'], None
		except Exception as e:
			return None, e
		
	async def dn2sid(self, dn):
		"""Fetches the objectSid of an object based on the DN"""
		try:
			query = '(distinguishedName=%s)' % escape_filter_chars(dn)
			async for entry, err in self.pagedsearch(query, ['objectSid']):
				if err is not None:
					raise err
				return entry['attributes']['objectSid'], None
		except Exception as e:
			return None, e
	
	async def dn2sam(self, dn):
		"""Fetches the sAMAccountName of an object based on the DN"""
		try:
			query = '(distinguishedName=%s)' % escape_filter_chars(dn)
			async for entry, err in self.pagedsearch(query, ['sAMAccountName']):
				if err is not None:
					raise err
				return entry['attributes']['sAMAccountName'], None
		except Exception as e:
			return None, e

	async def dnattrs(self, dn, attrs:List[str]):
		"""Fetches attributes of an object specified by DN"""
		try:
			query = '(distinguishedName=%s)' % escape_filter_chars(dn)
			async for entry, err in self.pagedsearch(query, attrs):
				if err is not None:
					raise err
				return entry['attributes'], None
			return None, None #no results
		except Exception as e:
			return None, e

	async def get_childobjects(self, dn):
		try:
			query = '(|(objectClass=container)(objectClass=organizationalUnit)(sAMAccountType=805306369)(objectClass=group)(&(objectCategory=person)(objectClass=user)))'
			attrs =['objectSid', 'objectClass', 'objectGUID', 'distinguishedName', 'sAMAccountName', 'sAMAccountType']
			async for entry, err in self.pagedsearch(query, attrs, tree=dn, search_scope=1):
				if err is not None:
					raise err
				yield entry['attributes'], None
		except Exception as e:
			yield None, e
   
	async def dnslistzones(self):
		"""Lists all DNS zones in the forest"""
		try:
			query = '(objectClass=dnsZone)'
			async for entry, err in self.pagedsearch(query, ['dc']):
				if err is not None:
					raise err
				yield(entry['attributes']['dc']), None
		except Exception as e:
			yield None, e

	async def dnsentries(self, zone = None, with_tombstones = False):
		"""Lists all DNS entries in the forest"""
		dnsroots = [
			'CN=MicrosoftDNS,CN=System,%s' % self._tree,
			'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % self._tree
		]

		async for entry, err in self.dnslistzones():
			if err is not None:
				raise err
			dnsroots.append('CN=MicrosoftDNS,DC=ForestDnsZones,DC=%s' % entry)

		try:
			for dnsroot in dnsroots:
				query = '(objectClass=dnsNode)'
				try:
					async for entry, err in self.pagedsearch(query, attributes=['dnsRecord','dNSTombstoned','name'], tree=dnsroot):
						if err is not None:
							raise err
						
						if 'name' not in entry['attributes'] or entry['attributes']['name'] is None:
							continue

						if 'dNSTombstoned' in entry['attributes'] and entry['attributes']['dNSTombstoned'] is True:
							if with_tombstones is False:
								continue
						
						if 'dnsRecord' not in entry['attributes']:
							continue

						for recorddata in entry['attributes']['dnsRecord']:
							yield dnsroot, entry['attributes']['name'], DNS_RECORD.from_bytes(recorddata), None
				
				except LDAPSearchException:
					if zone is None:
						pass
					else:
						raise Exception('Zone %s not found!' % zone)
		except Exception as e:
			yield None, None, None, e
	


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
