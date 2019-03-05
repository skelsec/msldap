from msldap.core.msldap import MSLDAP
from ldap3 import BASE
from msldap.core.ms_asn1 import *
from msldap.core.win_data_types import *

class LDAPRecon(MSLDAP):
	def __init__(self, *args, **kwargs):
		MSLDAP.__init__(self, *args, **kwargs)
		self.use_sspi = True
		self.connect()
		
	def get_netdomain(self, domain = None):
		"""
		gets the name of the current user's domain
		"""
		info = self.get_server_info()
		print(info)
		#print([x for x in info.__dict__])
		print([x for x in info.__dict__['other']])
		print(info.other['defaultNamingContext'])
		print(info.other['dnsHostName'])
		print(info.other['domainControllerFunctionality'])
		print(info.other['forestFunctionality'])
		
		
	def get_netforest(self, forest = None):
		"""
		gets the forest associated with the current user's domain
		"""
		raise Exception('Not implemented!')
	def get_netforestdomain(self, forest = None):
		"""
		gets all domains for the current forest
		"""
		raise Exception('Not implemented!')
	def get_netdomaincontroller(self, domain = None):
		"""
		gets the domain controllers for the current computer's domain
		"""
		raise Exception('Not implemented!')
	def get_netuser(self):
		"""
		returns all user objects, or the user specified (wildcard specifiable)
		"""
		raise Exception('Not implemented!')
	def add_netuser(self):
		"""
		adds a local or domain user
		"""
		raise Exception('Not implemented!')
	def get_netcomputer(self):
		"""
		gets a list of all current servers in the domain
		"""
		#logger.debug('Polling AD for all computer objects')
		ldap_filter = r'(&(sAMAccountType=805306369))'

		attributes = '*'
		for entry in self.pagedsearch(ldap_filter, attributes):
			print(entry)
		#logger.debug('Finished polling for entries!')
		
	def get_netprinter(self):
		"""
		gets an array of all current computers objects in a domain
		"""
		ldap_filter = r'(&(sAMAccountType=805306369)(objectCategory=printQueue))'

		attributes = '*'
		for entry in self.pagedsearch(ldap_filter, attributes):
			print(entry)

	def get_netou(self):
		"""
		gets data for domain organization units
		"""
		raise Exception('Not implemented!')
	def get_netsite(self):
		"""
		gets current sites in a domain
		"""
		raise Exception('Not implemented!')
	def get_netsubnet(self):
		"""
		gets registered subnets for a domain
		"""
		raise Exception('Not implemented!')
	def get_netgroup(self):
		"""
		gets a list of all current groups in a domain
		"""
		raise Exception('Not implemented!')
	def get_netgroupmember(self):
		"""
		gets a list of all current users in a specified domain group
		"""
		raise Exception('Not implemented!')
	def get_netlocalgroup(self):
		"""
		NOTE: this is not and LDAP function so it wont be implemnted here
		gets the members of a localgroup on a remote host or hosts
		"""
		raise Exception('Not implemented!')
	def add_netgroupuser(self):
		"""
		NOTE: this is not and LDAP function so it wont be implemnted here
		adds a local or domain user to a local or domain group
		"""
		raise Exception('Not implemented!')
	def get_netfileserver(self):
		"""
		NOTE: this is not and LDAP function so it wont be implemnted here
		get a list of file servers used by current domain users
		"""
		raise Exception('Not implemented!')
	def get_dfsshare(self):
		"""
		NOTE: this is not and LDAP function so it wont be implemnted here
		gets a list of all distribute file system shares on a domain
		"""
		raise Exception('Not implemented!')
	def get_netshare(self):
		"""
		NOTE: this is not and LDAP function so it wont be implemnted here
		gets share information for a specified server
		"""
		raise Exception('Not implemented!')
	def get_netloggedon(self):
		"""
		NOTE: this is not and LDAP function so it wont be implemnted here
		gets users actively logged onto a specified server
		"""
		raise Exception('Not implemented!')
	def get_netsession(self):
		"""
		NOTE: this is not and LDAP function so it wont be implemnted here
		gets active sessions on a specified server
		"""
		raise Exception('Not implemented!')
	def get_netrdpsession(self):
		"""
		NOTE: this is not and LDAP function so it wont be implemnted here
		gets active RDP sessions for a specified server (like qwinsta)
		"""
		raise Exception('Not implemented!')
	def get_netprocess(self):
		"""
		gets the remote processes and owners on a remote server
		"""
		raise Exception('Not implemented!')
	def get_userevent(self):
		"""
		returns logon or TGT events from the event log for a specified host
		"""
		raise Exception('Not implemented!')
	def get_adobject(self, sid):
		"""
		takes a domain SID and returns the user, group, or computer object associated with it
		"""
		ldap_filter = r'(objectSid=%s)' % str(sid)
		print(ldap_filter)
		attributes = '*'
		
		for entry in self.pagedsearch(ldap_filter, attributes):
			print(entry)
			
	def set_adobject(self):
		"""
		
		"""
		raise Exception('Not implemented!')
		
	def get_objectacl(self):
		"""
		Returns the ACLs associated with a specific active directory object.
		"""
		
		flags_value = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION
		req_flags = SDFlagsRequestValue({'Flags' : flags_value})
		
		ldap_filter = r'(objectClass=*)'
		attributes = '*'
		controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]
		
		for entry in self.pagedsearch(ldap_filter, attributes, controls = controls):
			#print([x for x in entry['raw_attributes']['nTSecurityDescriptor']])
			print(entry['raw_attributes']['objectsid'])
			sdec = SECURITY_DESCRIPTOR.from_bytes(entry['raw_attributes']['nTSecurityDescriptor'][0])
			print(sdec)
			input()
		
	def get_tokengroups(self, dn):
		"""
		returns the tokengroups attribute for a given DN
		"""
		ldap_filter = r'(distinguishedName=%s)' % dn
		attributes=['tokenGroups']
		print(self._tree)
		
		self._con.search(dn, ldap_filter, attributes=attributes, search_scope=BASE)
		print(len(self._con.response))
		for entry in self._con.response:
			for sid_data in entry['attributes']['tokenGroups']:
				yield SID.from_bytes(sid_data)
				
	def test(self):
		sids = []
		dn = 'CN=Administrator,CN=Users,DC=test,DC=corp'
		ldap_filter = r'(distinguishedName=%s)' % dn
		attributes=['tokenGroups']
		#print(self._tree)
		
		self._con.search(dn, ldap_filter, attributes=attributes, search_scope=BASE)
		#print(len(self._con.response))
		for entry in self._con.response:
			for sid_data in entry['attributes']['tokenGroups']:
				sids.append(SID.from_bytes(sid_data))
				
				
		flags_value = SDFlagsRequest.DACL_SECURITY_INFORMATION|SDFlagsRequest.GROUP_SECURITY_INFORMATION|SDFlagsRequest.OWNER_SECURITY_INFORMATION
		req_flags = SDFlagsRequestValue({'Flags' : flags_value})
		
		ldap_filter = r'(objectClass=*)'
		attributes = '*'
		controls = [('1.2.840.113556.1.4.801', True, req_flags.dump())]
		
		for entry in self.pagedsearch(ldap_filter, attributes, controls = controls):
			#print([x for x in entry['raw_attributes']['nTSecurityDescriptor']])
			#print(entry['raw_attributes']['objectsid'])
			if not 'nTSecurityDescriptor' in entry['raw_attributes']:
				continue
			sdec = SECURITY_DESCRIPTOR.from_bytes(entry['raw_attributes']['nTSecurityDescriptor'][0])
			for ace in sdec.Dacl.aces:
				for sid in sids:
					print(str(ace.Sid))
					if str(ace.Sid) == str(sid):
						print(entry['attributes']['distinguishedName'])
						print(str(ace))
						input()
"""	
Get-DNSZone
Get-GUIDMap
Get-NetOU
Get-NetSite
Get-NetSubnet
NetGroup
Get-NetGroupMember
Get-DFSshare
Get-NetGPO
Get-NetDomainTrust
"""
		
		
		
		
		
		