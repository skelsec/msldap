import os
import zipfile
import json
import base64
import datetime
import asyncio

from tqdm import tqdm

from msldap.external.bloodhoundpy.acls import parse_binary_acl
from msldap.external.bloodhoundpy.resolver import resolve_aces, WELLKNOWN_SIDS
from msldap.external.bloodhoundpy.utils import parse_gplink_string, is_filtered_container, is_filtered_container_child, reverse_dn_components, explode_dn
from msldap.commons.factory import LDAPConnectionFactory
from msldap.connection import MSLDAPClientConnection
from msldap.client import MSLDAPClient
from msldap.commons.adexplorer import Snapshot
from msldap import logger

async def dummy_print(msg):
	print(msg)

class MSLDAPDump2Bloodhound:
	def __init__(self, url: str or MSLDAPClient or LDAPConnectionFactory or MSLDAPClientConnection, progress = True, output_path = None, use_mp:bool=True, print_cb = None):
		self.debug = False
		self.ldap_url = url
		self.connection: MSLDAPClient = None
		self.ldapinfo = None
		self.domainname = None
		self.domainsid = None
		self.use_mp = use_mp
		self.mp_sdbatch_length = 5000
		self.print_cb = print_cb
		self.with_progress = progress
		if self.print_cb is None:
			self.print_cb = dummy_print

		self.DNs = {}
		self.DNs_sorted = {}
		self.ocache = {}
		self.schema = {}
		self.aces = {}
		self.computer_sidcache = {}
		self.token_map = {}

		self.curdate = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%S')
		self.zipfilepath = '%s_Bloodhound.zip' %  self.curdate
		if output_path is not None:
			self.zipfilepath = os.path.join(output_path, self.zipfilepath)
		self.zipfile = None
		self.MAX_ENTRIES_PER_FILE = 40000
		
		self.totals = {
			'user' : 0,
			'computer' : 0,
			'group' : 0,
			'ou' : 0,
			'gpo' : 0,
			'container' : 0,
			'domain' : 0,
			'trust' : 0
		}
	
	async def print(self, msg:str):
		await self.print_cb(msg)

	
	async def create_progress(self, label, total = None):
		if self.with_progress is True:
			return tqdm(desc = label, total=total)
		else:
			await self.print('[+] %s' % label)
			return None
	
	async def update_progress(self, pbar, value = 1):
		if pbar is None:
			return
		if self.with_progress is True:
			pbar.update(value)
	
	async def close_progress(self, pbar):
		if pbar is None:
			return
		if self.with_progress is True:
			pbar.close()
	
	def get_json_wrapper(self, enumtype):
		return {
			'data' : [],
			'meta': {
				'methods' : 0,
				'type': enumtype,
				'version': 5,
				'count': 0
			}
		}
		

	def split_json(self, enumtype, data):
		if data['meta']['count'] <= self.MAX_ENTRIES_PER_FILE:
			yield data
			return
		
		#split the data
		for i in range(0, data['meta']['count'], self.MAX_ENTRIES_PER_FILE):
			jsonstruct = {
				'data' : [],
				'meta': {
					'methods' : 0,
					'type': enumtype,
					'version': 5,
					'count': 0
				}
			}
			for entry in data['data'][i:i+self.MAX_ENTRIES_PER_FILE]:
				jsonstruct['data'].append(entry)
				jsonstruct['meta']['count'] += 1
			yield jsonstruct

	
	async def write_json_to_zip(self, enumtype, data, filepart = 0):
		if filepart == 0:
			filename = '%s_%s.json' % (self.curdate, enumtype)
		else:
			filename = '%s_%s_%02d.json' % (self.curdate, enumtype, filepart)
		self.zipfile.writestr(filename, json.dumps(data))

	
	async def lookup_dn_children(self, parent_dn):
		parent_dn = parent_dn.upper()
		parent_dn_reversed = reverse_dn_components(parent_dn)
		if parent_dn not in self.DNs:
			logger.debug('[BH] DN not found: %s' % parent_dn_reversed)
			return []

		branch = self.DNs_sorted
		level = 0
		for part in explode_dn(parent_dn_reversed):
			level += 1
			if part not in branch:
				logger.debug('[BH] Part not found: %s Full: %s Branch: %s Level: %s Parts: %s' % (part, parent_dn_reversed, branch.keys(), level, explode_dn(parent_dn_reversed)))
				return []
			branch = branch[part]

		res_dns = []
		for dnpart in branch:
			res_dns.append(dnpart + ',' + parent_dn)
			
		results = []
		for tdn in res_dns:
			if is_filtered_container_child(tdn):
				continue
			if tdn not in self.DNs:
				attrs, err = await self.connection.dnattrs(tdn, ['distinguishedName','objectGUID', 'objectClass','sAMAaccountType', 'sAMAccountName', 'objectSid', 'name'])
				if err is not None:
					raise err
				if attrs is None or len(attrs) == 0:
					logger.debug('[BH] Missing DN: %s' % tdn)
					continue
				res = self.resolve_entry(attrs)
				results.append({
					'ObjectIdentifier': res['objectid'].upper(),
					'ObjectType': res['type'].capitalize(),
				})
				continue
			entry = self.ocache[self.DNs[tdn]]
			results.append({
				'ObjectIdentifier': entry['ObjectIdentifier'].upper(),
				'ObjectType': entry['ObjectType'].capitalize() if entry['ObjectType'].lower() != 'ou' else 'OU',
			})
		
		return results

	async def dump_schema(self):
		pbar = await self.create_progress('Dumping schema')
		# manual stuff here...
		# https://learn.microsoft.com/en-us/windows/win32/adschema/c-foreignsecurityprincipal
		self.schema['foreignsecurityprincipal'] = '89e31c12-8530-11d0-afda-00c04fd930c9'
		
		async for entry, err in self.connection.get_all_schemaentry(['name', 'schemaIDGUID']):
			if err is not None:
				raise err
			await self.update_progress(pbar)
			self.schema[entry.name.lower()] = str(entry.schemaIDGUID)
		await self.close_progress(pbar)

	def add_ocache(self, dn, objectid, principal, otype, dns = '', spns = None):
		self.totals[otype] += 1
		if objectid in WELLKNOWN_SIDS:
			objectid = '%s-%s' % (self.domainname.upper(), objectid.upper())
		self.ocache[objectid] = {
			'dn' : dn.upper(),
			'ObjectIdentifier' : objectid,
			'principal' : principal,
			'ObjectType' : otype,
		}
		self.DNs[dn.upper()] = objectid
		if otype == 'computer':
			entry = {
				'ObjectIdentifier' : objectid,
				'ObjectType' : otype
			}
			if dns is None:
				dns = ''
			self.computer_sidcache[dns.lower()] = entry
			if spns is not None:
				for spn in spns:
					target = spn.split('/')[1]
					target = target.split(':')[0]
					self.computer_sidcache[target.lower()] = entry
	
	def resolve_entry(self, entry):
		# I really REALLY did not want to implement this
		resolved = {}
		account = entry.get('sAMAccountName', '')
		dn = entry.get('distinguishedName', '')
		resolved['objectid'] = entry.get('objectSid', '')
		resolved['principal'] = ('%s@%s' % (account, self.domainname)).upper()
		if 'sAMAaccountName' in entry:
			accountType = entry['sAMAccountType']
			object_class = entry['objectClass']
			if accountType in [268435456, 268435457, 536870912, 536870913]:
				resolved['type'] = 'Group'
			elif accountType in [805306368] or \
				 'msDS-GroupManagedServiceAccount' in object_class or \
				 'msDS-ManagedServiceAccount' in object_class:
				resolved['type'] = 'User'
			elif accountType in [805306369]:
				resolved['type'] = 'Computer'
				short_name = account.rstrip('$')
				resolved['principal'] = ('%s.%s' % (short_name, self.domainname)).upper()
			elif accountType in [805306370]:
				resolved['type'] = 'trustaccount'
			else:
				resolved['type'] = 'Domain'
			return resolved
		
		if 'objectGUID' in entry:
			resolved['objectid'] = entry['objectGUID']
			resolved['principal'] = ('%s@%s' % (entry.get('name', ''), self.domainname)).upper()
			object_class = entry.get('objectClass', [])
			if 'organizationalUnit' in object_class:
				resolved['type'] = 'OU'
			elif 'container' in object_class:
				resolved['type'] = 'Container'
			else:
				resolved['type'] = 'Base'
			return resolved

	async def dump_lookuptable(self):
		pbar = await self.create_progress('Generating lookuptable')
		# domains
		adinfo, err = await self.connection.get_ad_info()
		if err is not None:
			raise err
		self.domainsid = adinfo.objectSid
		self.add_ocache(adinfo.distinguishedName, adinfo.objectSid, '', 'domain')
		await self.update_progress(pbar)

		#trusts
		async for entry, err in self.connection.get_all_trusts(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'trust')
			await self.update_progress(pbar)

		#users
		async for entry, err in self.connection.get_all_users(['distinguishedName', 'objectSid', 'objectGUID', 'sAMAccountName']):
			if err is not None:
				raise err
			short_name = entry.sAMAccountName
			self.add_ocache(entry.distinguishedName, entry.objectSid, ('%s@%s' % (short_name, self.domainname)).upper(), 'user')
			await self.update_progress(pbar)

		#machines
		async for entry, err in self.connection.get_all_machines(['distinguishedName', 'objectSid', 'objectGUID', 'sAMAccountName', 'dNSHostName', 'servicePrincipalName']):
			if err is not None:
				raise err
			short_name = entry.sAMAccountName
			dns = entry.dNSHostName
			if dns is None:
				dns = ''

			self.add_ocache(entry.distinguishedName, entry.objectSid, ('%s@%s' % (short_name, self.domainname)).upper(), 'computer', dns, entry.servicePrincipalName)
			await self.update_progress(pbar)

		#groups
		async for entry, err in self.connection.get_all_groups(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectSid, '', 'group')
			await self.update_progress(pbar)

		#ous
		async for entry, err in self.connection.get_all_ous(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'ou')
			await self.update_progress(pbar)

		#containers
		async for entry, err in self.connection.get_all_containers(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			if is_filtered_container(entry.distinguishedName):
				continue
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'container')
			await self.update_progress(pbar)

		#gpos
		async for entry, err in self.connection.get_all_gpos(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'gpo')
			await self.update_progress(pbar)

		#foreignsecurityprincipal
		async for entry, err in self.connection.get_all_foreignsecurityprincipals(['name','sAMAccountName', 'objectSid', 'objectGUID', 'distinguishedName', 'objectClass']):
			bhentry = {}
			entry = entry['attributes']
			if 'container' in  entry.get('objectClass', []) is True:
				continue

			if entry['objectSid'] in WELLKNOWN_SIDS:
				bhentry['objectid'] = '%s-%s' % (self.domainname.upper(), entry['objectSid'].upper())
			bhentry['principal'] = self.domainname.upper()
			bhentry['type'] = 'foreignsecurityprincipal'
			if 'name' in entry:
				if entry['name'] in WELLKNOWN_SIDS:
					gname, sidtype = WELLKNOWN_SIDS[entry['name']]
					bhentry['type'] = sidtype.capitalize()
					bhentry['principal'] = '%s@%s' % (gname.upper(), self.domainname.upper())
					bhentry['objectid'] = '%s-%s' % (self.domainname.upper(), entry['objectSid'].upper())
				else:
					bhentry['objectid'] = entry['name']

			self.ocache[bhentry['objectid']] = {
				'dn' : entry['distinguishedName'].upper(),
				'ObjectIdentifier' : bhentry['objectid'],
				'principal' : bhentry['principal'],
				'ObjectType' : bhentry['type'],
			}
			self.DNs[entry['distinguishedName'].upper()] = bhentry['objectid']
			
		await self.close_progress(pbar)

		for dn in [reverse_dn_components(dn) for dn in self.DNs]:
			branch = self.DNs_sorted
			for part in explode_dn(dn):
				if part not in branch:
					branch[part.upper()] = {}
				branch = branch[part.upper()]
		
		if self.debug is True:
			with open('dn.json', 'w') as f:
				json.dump(self.DNs, f, indent=4)

			with open('dntree.json', 'w') as f:
				json.dump(self.DNs_sorted, f, indent=4)
	
	async def dump_acls(self):
		sdbatch = []
		tasks = []
		pbar = await self.create_progress('Dumping SDs', total=len(self.ocache))
		for sid in self.ocache:
			dn = self.ocache[sid]['dn']
			secdesc, err = await self.connection.get_objectacl_by_dn(dn)
			if err is not None:
				raise err
			dn = dn.upper()
			oentry = {
					'IsACLProtected' : None,
					'Properties' : {
						'haslaps' : 'ms-mcs-admpwd' in self.schema
					}
				}
			otype = self.ocache[sid]['ObjectType']
			if otype == 'trust':
				continue
			if otype == 'ou':
				otype = 'organizational-unit'
			if dn.upper() not in self.aces:
				if self.use_mp is True:
					from concurrent.futures import ProcessPoolExecutor
					sdbatch.append((dn, oentry, otype.lower(), secdesc, self.schema))
					if len(sdbatch) > self.mp_sdbatch_length:
						loop = asyncio.get_running_loop()
						with ProcessPoolExecutor() as executor:
							for sde in sdbatch:
								tasks.append(loop.run_in_executor(executor, parse_binary_acl, *sde))
						results = await asyncio.gather(*tasks)
						for dn, aces, relations in results:
							self.aces[dn.upper()] = (aces, relations)
						sdbatch = []
						tasks = []
				else:
					dn, aces, relations = parse_binary_acl(dn, oentry, otype.lower(), secdesc, self.schema)
					self.aces[dn.upper()] = (aces, relations)
			await self.update_progress(pbar)
		
		if len(sdbatch) != 0:
			loop = asyncio.get_running_loop()
			with ProcessPoolExecutor() as executor:
				for sde in sdbatch:
					tasks.append(loop.run_in_executor(executor, parse_binary_acl, *sde))
				results = await asyncio.gather(*tasks)
				for dn, aces, relations in results:
					self.aces[dn.upper()] = (aces, relations)
				sdbatch = []
				tasks = []
		await self.close_progress(pbar)
	
	async def resolve_gplink(self, gplinks):
		if gplinks is None:
			return []

		links = []
		for gplink_dn, options in parse_gplink_string(gplinks):
			link = {}
			link['IsEnforced'] = options == 2
			gplink_dn = gplink_dn.upper()
			if gplink_dn in self.DNs:
				lguid = self.ocache[self.DNs[gplink_dn]]['ObjectIdentifier']
			else:
				attrs, err = await self.connection.dnattrs(gplink_dn.upper(), ['objectGUID', 'objectSid'])
				if err is not None:
					raise err
				if attrs is None or len(attrs) == 0:
					logger.debug('[BH] Missing DN: %s' % gplink_dn)
					continue
				try:
					lguid = attrs['objectGUID']
				except:
					logger.debug('[BH] Missing GUID for %s' % gplink_dn)
					continue
			link['GUID'] = lguid.upper()
			links.append(link)
		return links

	def remove_hidden(self, entry):
		to_del = []
		for k in entry:
			if k.startswith('_'):
				to_del.append(k)
		for k in to_del:
			del entry[k]
		return entry

	async def dump_domains(self):
		pbar = await self.create_progress('Dumping domains', self.totals['domain'])
		adinfo, err = await self.connection.get_ad_info()
		if err is not None:
			raise err
		
		domainentry = adinfo.to_bh(self.domainname)
		
		meta, relations = self.aces[domainentry['Properties']['distinguishedname'].upper()]
		domainentry['IsACLProtected'] = meta['IsACLProtected']
		domainentry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
		domainentry['ChildObjects'] =  await self.lookup_dn_children(domainentry['Properties']['distinguishedname'])
		domainentry['Links'] = await self.resolve_gplink(domainentry['_gPLink'])

		jsonstruct = self.get_json_wrapper('domains')
		filectr = 0
		async for entry, err in self.connection.get_all_trusts():
			if err is not None:
				raise err
			domainentry['Trusts'].append(entry.to_bh())
   
		domainentry = self.remove_hidden(domainentry)
		jsonstruct['data'].append(domainentry)
		jsonstruct['meta']['count'] += 1
		if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
			await self.write_json_to_zip('domains', jsonstruct, filectr)
			jsonstruct = self.get_json_wrapper('domains')
			filectr += 1
		await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('domains', jsonstruct, filectr)
		await self.close_progress(pbar)
		if self.debug is True:
			with open('domains.json', 'w') as f:
				json.dump(jsonstruct, f)
	
	async def dump_users(self):
		pbar = await self.create_progress('Dumping users', self.totals['user'])

		jsonstruct = self.get_json_wrapper('users')
		filectr = 0
		async for ldapentry, err in self.connection.get_all_users():
			if err is not None:
				raise err
			
			entry = ldapentry.to_bh(self.domainname)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			
			if entry['_allowerdtodelegateto'] is not None:
				seen = {}
				for host in entry['_allowerdtodelegateto']:
					try:
						target = host.split('/')[1]
						target = target.split(':')[0]
					except IndexError:
						logger.debug('[BH] Invalid delegation target: %s', host)
						continue
					try:
						sid = self.computer_sidcache[target.lower()]
						if sid['ObjectIdentifier'] in seen:
							continue
						seen[sid['ObjectIdentifier']] = 1
						entry['AllowedToDelegate'].append(sid)
					except KeyError:
						if '.' in target:
							entry['AllowedToDelegate'].append(target.upper())
			entry = self.remove_hidden(entry)

			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('users', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('users')
				filectr += 1
			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('users', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('users.json', 'w') as f:
				json.dump(jsonstruct, f)
	
	async def dump_computers(self):
		pbar = await self.create_progress('Dumping computers', self.totals['computer'])
		jsonstruct = self.get_json_wrapper('computers')
		filectr = 0
		async for ldapentry, err in self.connection.get_all_machines():
			entry = ldapentry.to_bh(self.domainname)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			
			if entry['_allowedtoactonbehalfofotheridentity'] is not None:
				allowedacl = base64.b64decode(entry['_allowedtoactonbehalfofotheridentity'])
				_, entryres, relations = parse_binary_acl(entry['Properties']['distinguishedname'].upper(), entry, 'computer', allowedacl, self.schema)
				
				for ace in resolve_aces(relations, self.domainname, self.domainsid, self.ocache):
					if ace['RightName'] == 'Owner':
						continue
					if ace['RightName'] == 'GenericAll':
						entryres['AllowedToAct'].append({
							'ObjectIdentifier': ace['PrincipalSID'], 
							'ObjectType': ace['PrincipalType'].capitalize()
						})
			
			del entry['_allowedtoactonbehalfofotheridentity']
			if entry['Properties']['allowedtodelegate'] is not None:
				seen = {}
				for host in entry['Properties']['allowedtodelegate']:
					try:
						target = host.split('/')[1]
						target = target.split(':')[0]
					except IndexError:
						logger.debug('[BH] Invalid delegation target: %s', host)
						continue
					try:
						sid = self.computer_sidcache[target.lower()]
						if sid['ObjectIdentifier'] in seen:
							continue
						seen[sid['ObjectIdentifier']] = 1
						entry['AllowedToDelegate'].append(sid)
					except KeyError:
						if '.' in target:
							entry['AllowedToDelegate'].append({
								"ObjectIdentifier": target.upper(),
								"ObjectType": "Computer"
							})

			entry = self.remove_hidden(entry)
			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('computers', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('computers')
				filectr += 1
			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('computers', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('computers.json', 'w') as f:
				json.dump(jsonstruct, f)
   
	async def dump_groups(self):
		pbar = await self.create_progress('Dumping groups', self.totals['group'])
		jsonstruct = self.get_json_wrapper('groups')
		filectr = 0
		async for ldapentry, err in self.connection.get_all_groups():
			entry = ldapentry.to_bh(self.domainname)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			
			if ldapentry.member is not None:
				for member in ldapentry.member:
					if member.upper() in self.DNs:
						oid = self.DNs[member.upper()]
						entry['Members'].append({
							'ObjectIdentifier' : self.ocache[oid]['ObjectIdentifier'],
							'ObjectType' : self.ocache[oid]['ObjectType'].capitalize()
						})
					else:
						if member.find('ForeignSecurityPrincipals') != -1:
							continue
	  
			entry = self.remove_hidden(entry)
			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('groups', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('groups')
				filectr += 1
			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('groups', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('groups.json', 'w') as f:
				json.dump(jsonstruct, f)

	async def dump_gpos(self):
		pbar = await self.create_progress('Dumping GPOs', self.totals['gpo'])
		jsonstruct = self.get_json_wrapper('gpos')
		filectr = 0
		async for ldapentry, err in self.connection.get_all_gpos():
			entry = ldapentry.to_bh(self.domainname, self.domainsid)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)      
			entry = self.remove_hidden(entry)

			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('gpos', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('gpos')
				filectr += 1
			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('gpos', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('gpos.json', 'w') as f:
				json.dump(jsonstruct, f)

	async def dump_ous(self):
		pbar = await self.create_progress('Dumping OUs', self.totals['ou'])
		jsonstruct = self.get_json_wrapper('ous')
		filectr = 0

		async for ldapentry, err in self.connection.get_all_ous():
			if err is not None:
				raise err
			entry = ldapentry.to_bh(self.domainname, self.domainsid)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			entry['ChildObjects'] =  await self.lookup_dn_children(entry['Properties']['distinguishedname'])
			entry['Links'] = await self.resolve_gplink(entry['_gPLink'])
			entry = self.remove_hidden(entry)

			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('ous', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('ous')
				filectr += 1

			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('ous', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('ous.json', 'w') as f:
				json.dump(jsonstruct, f)
	
	async def dump_containers(self):
		pbar = await self.create_progress('Dumping Containers', self.totals['container'])
		jsonstruct = self.get_json_wrapper('containers')
		filectr = 0
		async for ldapentry, err in self.connection.get_all_containers():
			if err is not None:
				raise err
			if is_filtered_container(ldapentry.distinguishedName):
				continue
			entry = ldapentry.to_bh(self.domainname, self.domainsid)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			entry['ChildObjects'] =  await self.lookup_dn_children(entry['Properties']['distinguishedname'])
			entry = self.remove_hidden(entry)

			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('containers', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('containers')
				filectr += 1
			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('containers', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('containers.json', 'w') as f:
				json.dump(jsonstruct, f)
	
	async def dump_ldap(self):
		if isinstance(self.ldap_url, str):
			if self.ldap_url.startswith('adexplorer://'):
				self.ldap_url = self.ldap_url[13:]
				await self.print('[+] Parsing ADEXPLORER Snapshot...')
				self.connection = await Snapshot.from_file(self.ldap_url)
				self.ldap_url = self.connection
				await self.print('[+] Parsing done!')

		if isinstance(self.ldap_url, Snapshot) is False:
			if isinstance(self.ldap_url, str):
				factory = LDAPConnectionFactory.from_url(self.ldap_url)
				self.connection = factory.get_client()
				self.connection.keepalive = True
			if isinstance(self.ldap_url, LDAPConnectionFactory):
				self.connection = self.ldap_url.get_client()
				self.connection.keepalive = True
			if isinstance(self.ldap_url, MSLDAPClient):
				self.connection = self.ldap_url
			
			if isinstance(self.ldap_url, MSLDAPClientConnection):
				self.connection = MSLDAPClient(None, None, connection = self.ldap_url)
			
			await self.print('[+] Connecting to LDAP server')
			self.connection.keepalive = True
			_, err = await self.connection.connect()
			if err is not None:
				raise err
			await self.print('[+] Connected to LDAP serrver')
			
			self.ldapinfo = self.connection.get_server_info()
			self.domainname = self.ldapinfo['defaultNamingContext'].upper().replace('DC=','').replace(',','.')
		else:
			self.domainname = self.connection.rootdomain.upper().replace('DC=','').replace(',','.')
		
		await self.dump_schema()
		await self.dump_lookuptable()
		await self.dump_acls()
		with zipfile.ZipFile(self.zipfilepath, 'w', zipfile.ZIP_DEFLATED) as self.zipfile:
			await self.dump_domains()
			await self.dump_users()
			await self.dump_computers()
			await self.dump_groups()
			await self.dump_gpos()
			await self.dump_ous()
			await self.dump_containers()
		await self.print('[+] Bloodhound data saved to %s' % self.zipfilepath)

	
	async def run(self):
		await self.dump_ldap()