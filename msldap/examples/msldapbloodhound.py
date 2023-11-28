import zipfile
import json
import base64
import asyncio
import datetime

from tqdm import tqdm

from msldap.external.bloodhoundpy.acls import parse_binary_acl
from msldap.external.bloodhoundpy.resolver import resolve_aces, WELLKNOWN_SIDS
from msldap.commons.utils import is_filtered_container, is_filtered_container_child
from msldap.commons.factory import LDAPConnectionFactory



def reverse_dn_components(dn:str):
	rdns = ','.join(reversed(dn.split(',')))
	return rdns.upper()

def explode_dn(dn):
	parts = []
	esc = False
	part = ''

	for char in dn:
		if esc:
			part += char
			esc = False
		elif char == '\\':
			esc = True
			part += char
		elif char == ',':
			if part:
				parts.append(part)
				part = ''
		else:
			part += char

	if part:
		parts.append(part)

	return parts


def parse_gplink_string(linkstr):
	if not linkstr:
		return
	for links in linkstr.split('[LDAP://')[1:]:
		dn, options = links.rstrip('][').split(';')
		yield dn, int(options)


class MSLDAPDump2Bloodhound:
	def __init__(self, url):
		self.ldap_url = url
		self.connection = None
		self.ldapinfo = None
		self.domainname = None
		self.domainsid = None
		self.with_progress = True

		self.DNs = {}
		self.DNs_sorted = {}
		self.ocache = {}
		self.schema = {}
		self.aces = {}
		self.computer_sidcache = {}
		self.token_map = {}

		self.curdate = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%S')
		self.zipfilepath = '%s_Bloodhound.zip' %  self.curdate
		self.zipfile = None
		
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
	
	
	def create_progress(self, label, total = None):
		if self.with_progress is True:
			return tqdm(desc = label, total=total)
		else:
			print('[+] %s' % label)
			return None
	
	def update_progress(self, pbar, value = 1):
		if pbar is None:
			return
		if self.with_progress is True:
			pbar.update(value)
	
	def close_progress(self, pbar):
		if pbar is None:
			return
		if self.with_progress is True:
			pbar.close()
	
	async def lookup_dn_children(self, parent_dn):
		parent_dn = parent_dn.upper()
		parent_dn_reversed = reverse_dn_components(parent_dn)
		if parent_dn not in self.DNs:
			print('DN not found: %s' % parent_dn_reversed)
			return []

		branch = self.DNs_sorted
		level = 0
		for part in explode_dn(parent_dn_reversed):
			level += 1
			if part not in branch:
				print('Part not found: %s Full: %s Branch: %s Level: %s Parts: %s' % (part, parent_dn_reversed, branch.keys(), level, explode_dn(parent_dn_reversed)))
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
				print('Missing %s' % tdn)
				continue
				#attrs, err = await self.connection.dnattrs(tdn, ['objectGUID', 'objectClass','sAMAaccountType', 'sAMAccountName', 'objectSid'])
				#print(attrs)
			entry = self.ocache[self.DNs[tdn]]
			results.append({
				'ObjectIdentifier': entry['ObjectIdentifier'].upper(),
				'ObjectType': entry['ObjectType'].capitalize() if entry['ObjectType'].lower() != 'ou' else 'OU',
			})
		
		return results

	async def dump_schema(self):
		pbar = self.create_progress('Dumping schema')
		async for entry, err in self.connection.get_all_schemaentry(['name', 'schemaIDGUID']):
			if err is not None:
				raise err
			self.update_progress(pbar)
			self.schema[entry.name.lower()] = str(entry.schemaIDGUID)
		self.close_progress(pbar)

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

	async def dump_lookuptable(self):
		pbar = self.create_progress('Generating lookuptable')
		# domains
		adinfo, err = await self.connection.get_ad_info()
		if err is not None:
			raise err
		self.domainsid = adinfo.objectSid
		self.add_ocache(adinfo.distinguishedName, adinfo.objectSid, '', 'domain')
		self.update_progress(pbar)

		#trusts
		async for entry, err in self.connection.get_all_trusts(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'trust')
			self.update_progress(pbar)

		#users
		async for entry, err in self.connection.get_all_users(['distinguishedName', 'objectSid', 'objectGUID', 'sAMAccountName']):
			if err is not None:
				raise err
			short_name = entry.sAMAccountName
			self.add_ocache(entry.distinguishedName, entry.objectSid, ('%s@%s' % (short_name, self.domainname)).upper(), 'user')
			self.update_progress(pbar)

		#machines
		async for entry, err in self.connection.get_all_machines(['distinguishedName', 'objectSid', 'objectGUID', 'sAMAccountName', 'dNSHostName', 'servicePrincipalName']):
			if err is not None:
				raise err
			short_name = entry.sAMAccountName
			dns = entry.dNSHostName
			if dns is None:
				dns = ''
			self.add_ocache(entry.distinguishedName, entry.objectSid, ('%s@%s' % (short_name, self.domainname)).upper(), 'computer', dns, entry.servicePrincipalName)
			self.update_progress(pbar)

		#groups
		async for entry, err in self.connection.get_all_groups(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectSid, '', 'group')
			self.update_progress(pbar)

		#ous
		async for entry, err in self.connection.get_all_ous(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'ou')
			self.update_progress(pbar)

		#containers
		async for entry, err in self.connection.get_all_containers(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			if is_filtered_container(entry.distinguishedName):
				continue
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'container')
			self.update_progress(pbar)

		#gpos
		async for entry, err in self.connection.get_all_gpos(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'gpo')
			self.update_progress(pbar)

		#foreignsecurityprincipal
		query = '(&(objectClass=foreignSecurityPrincipal)(objectCategory=foreignSecurityPrincipal))'
		async for entry, err in self.connection.pagedsearch(query, ['name','sAMAccountName', 'objectSid', 'objectGUID', 'distinguishedName', 'objectClass']):
			bhentry = {}
			entry = entry['attributes']
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
   
			print(entry)
			
		self.close_progress(pbar)

		for dn in [reverse_dn_components(dn) for dn in self.DNs]:
			branch = self.DNs_sorted
			for part in explode_dn(dn):
				if part not in branch:
					branch[part.upper()] = {}
				branch = branch[part.upper()]
		
		with open('dn.json', 'w') as f:
			json.dump(self.DNs, f, indent=4)

		with open('dntree.json', 'w') as f:
			json.dump(self.DNs_sorted, f, indent=4)
	
	async def dump_acls(self):
		pbar = self.create_progress('Dumping SDs', total=len(self.ocache))
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
				aces, relations = parse_binary_acl(oentry, otype.lower(), secdesc, self.schema)
				self.aces[dn.upper()] = (aces, relations)
			self.update_progress(pbar)
		self.close_progress(pbar)
	
	async def resolve_gplink(self, gplinks):
		if gplinks is None:
			return []

		links = []
		for gplink_dn, options in parse_gplink_string(gplinks):
			link = {}
			link['IsEnforced'] = options == 2
			if reverse_dn_components(gplink_dn.upper()) in self.DNs:
				lguid = self.DNs[reverse_dn_components(gplink_dn.upper())]['ObjectIdentifier']
			else:
				attrs, err = await self.connection.dnattrs(gplink_dn, ['objectGUID', 'objectSid'])
				if err is not None:
					raise err
				lguid = attrs['objectGUID']
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
		pbar = self.create_progress('Dumping domains', self.totals['domain'])
		jsonstruct = {
			'data' : [],
			'meta': {
				'methods' : 0,
				'type': 'domains',
				'version': 5,
				'count': 0
			}
		}

		adinfo, err = await self.connection.get_ad_info()
		if err is not None:
			raise err
		
		domainentry = adinfo.to_bh(self.domainname)
		meta, relations = self.aces[domainentry['Properties']['distinguishedname'].upper()]
		domainentry['IsACLProtected'] = meta['IsACLProtected']
		domainentry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
		domainentry['ChildObjects'] =  await self.lookup_dn_children(domainentry['Properties']['distinguishedname'])
		domainentry['Links'] = await self.resolve_gplink(domainentry['_gPLink'])

		async for entry, err in self.connection.get_all_trusts():
			if err is not None:
				raise err
			domainentry['Trusts'].append(entry.to_bh())
   
		domainentry = self.remove_hidden(domainentry)
		jsonstruct['data'].append(domainentry)
		jsonstruct['meta']['count'] += 1
		self.update_progress(pbar)
		
		self.zipfile.writestr('%s_domains.json' % self.curdate, json.dumps(jsonstruct))
		self.close_progress(pbar)
		with open('domains.json', 'w') as f:
			json.dump(jsonstruct, f)
	
	async def dump_users(self):
		pbar = self.create_progress('Dumping users', self.totals['user'])
		jsonstruct = {
			'data' : [],
			'meta': {
				'methods' : 0,
				'type': 'users',
				'version': 5,
				'count': 0
			}
		}

		async for ldapentry, err in self.connection.get_all_users():
			entry = ldapentry.to_bh(self.domainname)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			
			if entry['_allowerdtodelegateto'] is not None:
				seen = []
				for host in entry['_allowerdtodelegateto']:
					try:
						target = host.split('/')[1]
						target = target.split(':')[0]
					except IndexError:
						print('[!] Invalid delegation target: %s', host)
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
			self.update_progress(pbar)
		
		self.zipfile.writestr('%s_users.json' % self.curdate, json.dumps(jsonstruct))
		self.close_progress(pbar)
		with open('users.json', 'w') as f:
			json.dump(jsonstruct, f)
	
	async def dump_computers(self):
		pbar = self.create_progress('Dumping computers', self.totals['computer'])
		jsonstruct = {
			'data' : [],
			'meta': {
				'methods' : 0,
				'type': 'computers',
				'version': 5,
				'count': 0
			}
		}

		async for ldapentry, err in self.connection.get_all_machines():
			entry = ldapentry.to_bh(self.domainname)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			
			if entry['_allowedtoactonbehalfofotheridentity'] is not None:
				allowedacl = base64.b64decode(entry['_allowedtoactonbehalfofotheridentity'])
				entryres, relations = parse_binary_acl(entry, 'computer', allowedacl, self.schema)
				
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
						print('[!] Invalid delegation target: %s', host)
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
			self.update_progress(pbar)
		
		self.zipfile.writestr('%s_computers.json' % self.curdate, json.dumps(jsonstruct))
		self.close_progress(pbar)
		with open('computers.json', 'w') as f:
			json.dump(jsonstruct, f)
   
	async def dump_groups(self):
		pbar = self.create_progress('Dumping groups', self.totals['group'])
		jsonstruct = {
			'data' : [],
			'meta': {
				'methods' : 0,
				'type': 'groups',
				'version': 5,
				'count': 0
			}
		}

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
			self.update_progress(pbar)
		
		self.zipfile.writestr('%s_groups.json' % self.curdate, json.dumps(jsonstruct))
		self.close_progress(pbar)
		with open('groups.json', 'w') as f:
			json.dump(jsonstruct, f)

	async def dump_gpos(self):
		pbar = self.create_progress('Dumping GPOs', self.totals['gpo'])
		jsonstruct = {
			'data' : [],
			'meta': {
				'methods' : 0,
				'type': 'gpos',
				'version': 5,
				'count': 0
			}
		}

		async for ldapentry, err in self.connection.get_all_gpos():
			entry = ldapentry.to_bh(self.domainname, self.domainsid)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)      
			entry = self.remove_hidden(entry)

			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			self.update_progress(pbar)
		
		self.zipfile.writestr('%s_gpos.json' % self.curdate, json.dumps(jsonstruct))
		self.close_progress(pbar)
		with open('gpos.json', 'w') as f:
			json.dump(jsonstruct, f)

	async def dump_ous(self):
		pbar = self.create_progress('Dumping OUs', self.totals['ou'])
		jsonstruct = {
			'data' : [],
			'meta': {
				'methods' : 0,
				'type': 'ous',
				'version': 5,
				'count': 0
			}
		}

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
			self.update_progress(pbar)
		
		self.zipfile.writestr('%s_ous.json' % self.curdate, json.dumps(jsonstruct))
		self.close_progress(pbar)
		with open('ous.json', 'w') as f:
			json.dump(jsonstruct, f)
	
	async def dump_containers(self):
		pbar = self.create_progress('Dumping Containers', self.totals['container'])
		jsonstruct = {
			'data' : [],
			'meta': {
				'methods' : 0,
				'type': 'containers',
				'version': 5,
				'count': 0
			}
		}
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
			self.update_progress(pbar)
		
		self.zipfile.writestr('%s_containers.json' % self.curdate, json.dumps(jsonstruct))
		self.close_progress(pbar)
		with open('containers.json', 'w') as f:
			json.dump(jsonstruct, f)
	
	async def dump_ldap(self):
		print('[+] Connecting to LDAP server')
		self.conn_url = LDAPConnectionFactory.from_url(self.ldap_url)
		self.connection = self.conn_url.get_client()
		self.connection.keepalive = True
		_, err = await self.connection.connect()
		if err is not None:
			raise err
		self.ldapinfo = self.connection.get_server_info()
		self.domainname = self.ldapinfo['defaultNamingContext'].upper().replace('DC=','').replace(',','.')

		print('[+] Connected to LDAP serrver')
		
		
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


	
	async def run(self):
		await self.dump_ldap()

async def amain():
	args = parser.parse_args()
	msldap = MSLDAPDump2Bloodhound(args.url)
	await msldap.run()

if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser(description='Bloodhound collector for MSLDAP')
	parser.add_argument('url', help='LDAP connection URL')
	print("""
WARNING: This script is still in development. It is not guaranteed to provide the same results as the original Bloodhound collector.
""")
	asyncio.run(amain())
