#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import asyncio
import traceback
import logging
import csv
import shlex
import datetime
import copy
import typing

from msldap.external.aiocmd.aiocmd import aiocmd
from msldap.external.asciitree.asciitree import LeftAligned
from tqdm import tqdm

from msldap import logger
from asysocks import logger as sockslogger
from msldap.client import MSLDAPClient
from msldap.commons.factory import LDAPConnectionFactory
from msldap.ldap_objects import MSADUser, MSADMachine, MSADUser_TSV_ATTRS

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.ace import ACCESS_ALLOWED_OBJECT_ACE, ADS_ACCESS_MASK, AceFlags,\
	ACE_OBJECT_PRESENCE, ACEType
from winacl.dtyp.sid import SID
from winacl.dtyp.guid import GUID

from msldap.ldap_objects.adcertificatetemplate import MSADCertificateTemplate,\
	EX_RIGHT_CERTIFICATE_ENROLLMENT, CertificateNameFlag
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest


class MSLDAPClientConsole(aiocmd.PromptToolkitCmd):
	def __init__(self, url = None):
		aiocmd.PromptToolkitCmd.__init__(self, ignore_sigint=False) #Setting this to false, since True doesnt work on windows...
		self.conn_url = None
		if url is not None:
			self.conn_url = LDAPConnectionFactory.from_url(url)
		self.connection = None
		self.adinfo = None
		self.ldapinfo = None
		self.domain_name = None

	async def do_login(self, url = None):
		"""Performs connection and login"""
		try:			
			if self.conn_url is None and url is None:
				print('Not url was set, cant do logon')
			if url is not None:
				self.conn_url = LDAPConnectionFactory.from_url(url)

			logger.debug(self.conn_url.get_credential())
			logger.debug(self.conn_url.get_target())
			
			self.connection = self.conn_url.get_client()
			_, err = await self.connection.connect()
			if err is not None:
				raise err
			print('BIND OK!')
			self.prompt = self.connection._tree + ' > '
			
			return True
		except:
			traceback.print_exc()
			return False

	async def do_ldapinfo(self, show = True):
		"""Prints detailed LDAP connection info (DSA)"""
		try:
			if self.ldapinfo is None:
				self.ldapinfo = self.connection.get_server_info()
			if show is True:
				for k in self.ldapinfo:
					print('%s : %s' % (k, self.ldapinfo[k]))
			return True
		except:
			traceback.print_exc()
			return False

	async def do_adinfo(self, show = True):
		"""Prints detailed Active Driectory info"""
		try:
			if self.adinfo is None:
				self.adinfo = self.connection._ldapinfo
				self.domain_name = self.adinfo.distinguishedName.replace('DC','').replace('=','').replace(',','.')
			if show is True:
				print(self.adinfo)
			return True
		except:
			traceback.print_exc()
			return False

	async def do_spns(self):
		"""Fetches kerberoastable user accounts"""
		try:
			await self.do_ldapinfo(False)
			async for user, err in self.connection.get_all_service_users():
				if err is not None:
					raise err
				print(user.sAMAccountName)
			
			return True
		except:
			traceback.print_exc()
			return False

	async def do_asrep(self):
		"""Fetches ASREP-roastable user accounts"""
		try:
			await self.do_ldapinfo(False)
			async for user, err in self.connection.get_all_knoreq_users():
				if err is not None:
					raise err
				print(user.sAMAccountName)
			return True
		except:
			traceback.print_exc()
			return False

	async def do_computeraddr(self):
		"""Fetches all computer accounts"""
		try:
			await self.do_adinfo(False)
			#machine_filename = '%s_computers_%s.txt' % (self.domain_name, datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
		
			async for machine, err in self.connection.get_all_machines(attrs=['sAMAccountName', 'dNSHostName']):
				if err is not None:
					raise err
					
				dns = machine.dNSHostName
				if dns is None:
					dns = '%s.%s' % (machine.sAMAccountName[:-1], self.domain_name)

				print(str(dns))
			return True
		except:
			traceback.print_exc()
			return False

	async def do_dump(self):
		"""Fetches ALL user and machine accounts from the domain with a LOT of attributes"""
		try:
			await self.do_adinfo(False)
			await self.do_ldapinfo(False)
			
			users_filename = 'users_%s.tsv' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			pbar = tqdm(desc = 'Writing users to file %s' % users_filename)
			with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
				async for user, err in self.connection.get_all_users():
					if err is not None:
						raise err
					pbar.update()
					f.write('\t'.join(user.get_row(MSADUser_TSV_ATTRS))+'\n')
			print('Users dump was written to %s' % users_filename)
			
			users_filename = 'computers_%s.tsv' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			pbar = tqdm(desc = 'Writing computers to file %s' % users_filename)
			with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
				async for user, err in self.connection.get_all_machines():
					if err is not None:
						raise err
					pbar.update()
					f.write('\t'.join(user.get_row(MSADUser_TSV_ATTRS))+'\n')
			print('Computer dump was written to %s' % users_filename)
			return True
		except:
			traceback.print_exc()
			return False

	async def do_cd(self, path):
		"""Change current work directory"""
		self.connection._tree = path
		self.prompt = self.connection._tree + ' > '
		return True

	async def do_ls(self):
		"""Print objects in current work directory"""
		tree_data = await self.connection.get_tree_plot(self.connection._tree, level=1)
		root = list(tree_data.keys())[0]
		for dn in tree_data[root].keys():
			print(dn)
		return True

	async def do_cat(self, dn, attributes="*"):
		"""Print attributes of object"""
		attributes = attributes.split(",")
		async for entry, err in self.connection.pagedsearch(query="(distinguishedName=%s)"%dn, attributes=attributes):
			if err is not None:
				raise err
			for attr in entry["attributes"]:
				if type(entry["attributes"][attr]) == list:
					for val in entry["attributes"][attr]:
						print("%s: %s" % (attr, val))
				else:
					val = entry["attributes"][attr]
					print("%s: %s" % (attr, val))
		return True

	async def do_modify(self, dn, attribute, value):
		"""Modify an attribute of object"""
		changes = {
			attribute : [('replace', [value.encode()])]
		}

		_, err = await self.connection.modify(dn, changes)
		if err is not None:
			raise err
		
		print('Modify OK!')
		return True

	async def do_query(self, query, attributes = "-"):
		"""Performs a raw LDAP query against the server. Secondary parameter is the requested attributes SEPARATED WITH COMMA (,)"""
		try:
			await self.do_ldapinfo(False)
			if attributes is None:
				attributes = '*'
			if attributes.find(','):
				attributes = attributes.split(',')
			logging.debug('Query: %s' % (query))
			logging.debug('Attributes: %s' % (attributes))
			async for entry, err in self.connection.pagedsearch(query, attributes):
				if err is not None:
					raise err
				print(entry)
			return True
		except:
			traceback.print_exc()
			return False

	async def do_tree(self, dn = None, level = 1):
		"""Prints a tree from the given DN (if not set, the top) and with a given depth (default: 1)"""
		try:
			await self.do_ldapinfo(False)
			if level is None:
				level = 1
			level = int(level)
			if dn is not None:
				try:
					int(dn)
				except:
					pass
				else:
					level = int(dn)
					dn = None
					
			if dn is None:
				await self.do_ldapinfo(False)
				dn = self.connection._tree
			logging.debug('Tree on %s' % dn)
			tree_data = await self.connection.get_tree_plot(dn, level)
			tr = LeftAligned()
			print(tr(tree_data))

			return True
		except:
			traceback.print_exc()
			return False

	async def do_user(self, samaccountname, to_print=True):
		"""Feteches a user object based on the sAMAccountName of the user"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			user, err = await self.connection.get_user(samaccountname)
			if err is not None:
				raise err

			if to_print is True:
				if user is None:
					print('User not found!')
				else:
					print(user)
			
			return user
		except:
			traceback.print_exc()
			return False

	async def do_machine(self, samaccountname):
		"""Feteches a machine object based on the sAMAccountName of the machine"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			machine, err = await self.connection.get_machine(samaccountname)
			if err is not None:
				raise err
			if machine is None:
				print('machine not found!')
			else:
				print(machine)
				####TEST
				x = SECURITY_DESCRIPTOR.from_bytes(machine.allowedtoactonbehalfofotheridentity)
				print(x)
			
			return True
		except:
			traceback.print_exc()
			return False

	async def do_schemaentry(self, cn):
		"""Feteches a schema object entry object based on the DN of the object (must start with CN=)"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			schemaentry, err = await self.connection.get_schemaentry(cn)
			if err is not None:
				raise err
			
			print(str(schemaentry))
			return True
		except:
			traceback.print_exc()
			return False

	async def do_allschemaentry(self):
		"""Feteches all schema object entry objects"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			async for schemaentry, err in self.connection.get_all_schemaentry():
				if err is not None:
					raise err
				
				print(str(schemaentry))
			return True
		except:
			traceback.print_exc()
			return False

	#async def do_addallowedtoactonbehalfofotheridentity(self, target_name, add_computer_name):
	#	"""Adds a SID to the msDS-AllowedToActOnBehalfOfOtherIdentity protperty of target_dn"""
	#	try:
	#		await self.do_ldapinfo(False)
	#		await self.do_adinfo(False)
	#
	#		try:
	#			new_owner_sid = SID.from_string(sid)
	#		except:
	#			print('Incorrect SID!')
	#			return False, Exception('Incorrect SID')
	#
	#
	#		target_sd = None
	#		if target_attribute is None or target_attribute == '':
	#			target_attribute = 'nTSecurityDescriptor'
	#			res, err = await self.connection.get_objectacl_by_dn(target_dn)
	#			if err is not None:
	#				raise err
	#			target_sd = SECURITY_DESCRIPTOR.from_bytes(res)
	#		else:
	#			
	#			query = '(distinguishedName=%s)' % target_dn
	#			async for entry, err in self.connection.pagedsearch(query, [target_attribute]):
	#				if err is not None:
	#					raise err
	#				print(entry['attributes'][target_attribute])
	#				target_sd = SECURITY_DESCRIPTOR.from_bytes(entry['attributes'][target_attribute])
	#				break
	#			else:
	#				print('Target DN not found!')
	#				return False, Exception('Target DN not found!')
	#
	#		print(target_sd)
	#		new_sd = copy.deepcopy(target_sd)
	#		new_sd.Owner = new_owner_sid
	#		print(new_sd)
	#
	#		changes = {
	#			target_attribute : [('replace', [new_sd.to_bytes()])]
	#		}
	#		_, err = await self.connection.modify(target_dn, changes)
	#		if err is not None:
	#			raise err
	#
	#		print('Change OK!')
	#	except:
	#		traceback.print_exc()

	async def do_changeowner(self, new_owner_sid, target_dn, target_attribute = None):
		"""Changes the owner in a Security Descriptor to the new_owner_sid on an LDAP object or on an LDAP object's attribute identified by target_dn and target_attribute. target_attribute can be omitted to change the target_dn's SD's owner"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)

			_, err = await self.connection.change_priv_owner(new_owner_sid, target_dn, target_attribute = target_attribute)
			if err is not None:
				raise err
		except:
			traceback.print_exc()
			return False

	async def do_addprivdcsync(self, user_dn, forest = None):
		"""Adds DCSync rights to the given user by modifying the forest's Security Descriptor to add GetChanges and GetChangesAll ACE"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)

			_, err = await self.connection.add_priv_dcsync(user_dn, self.adinfo.distinguishedName)
			if err is not None:
				raise err

			print('Change OK!')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_addprivaddmember(self, user_dn, group_dn):
		"""Adds AddMember rights to the user on the group specified by group_dn"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)

			_, err = await self.connection.add_priv_addmember(user_dn, group_dn)
			if err is not None:
				raise err

			print('Change OK!')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_setsd(self, target_dn, sddl):
		"""Updates the security descriptor of an object"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
	
			try:
				new_sd = SECURITY_DESCRIPTOR.from_sddl(sddl)
			except:
				print('Incorrect SDDL input!')
				return False, Exception('Incorrect SDDL input!')
	
			_, err = await self.connection.set_objectacl_by_dn(target_dn, new_sd.to_bytes())
			if err is not None:
				raise err
			print('Change OK!')
			return True
		except:
			print('Erro while updating security descriptor!')
			traceback.print_exc()
			return False
			
	async def do_getsd(self, dn):
		"""Feteches security info for a given DN"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			sec_info, err = await self.connection.get_objectacl_by_dn(dn)
			if err is not None:
				raise err
			sd = SECURITY_DESCRIPTOR.from_bytes(sec_info)
			print(sd.to_sddl())
			return True
		except:
			traceback.print_exc()
			return False

	async def do_gpos(self):
		"""Feteches security info for a given DN"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			async for gpo, err in self.connection.get_all_gpos():
				if err is not None:
					raise err
				print(gpo)
			
			return True
		except:
			traceback.print_exc()
			return False

	async def do_laps(self):
		"""Feteches all laps passwords"""
		try:
			async for entry, err in self.connection.get_all_laps():
				if err is not None:
					raise err
				pwd = '<MISSING>'
				if 'ms-Mcs-AdmPwd' in entry['attributes']:
					pwd = entry['attributes']['ms-Mcs-AdmPwd']
				print('%s : %s' % (entry['attributes']['cn'], pwd))
			
			return True
		except:
			traceback.print_exc()
			return False

	async def do_groupmembership(self, dn):
		"""Feteches names all groupnames the user is a member of for a given DN"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			group_sids = []
			async for group_sid, err in self.connection.get_tokengroups(dn):
				if err is not None:
					raise err
				group_sids.append(group_sids)
				group_dn, err = await self.connection.get_dn_for_objectsid(group_sid)
				if err is not None:
					raise err
				print('%s - %s' % (group_dn, group_sid))
				
			if len(group_sids) == 0:
				print('No memberships found')
			
			return True
		except Exception as e:
			traceback.print_exc()
			return False

	async def do_bindtree(self, newtree):
		"""Changes the LDAP TREE for future queries. 
				 MUST be DN format eg. 'DC=test,DC=corp'
				 !DANGER! Switching tree to a tree outside of the domain will trigger a connection to that domain, leaking credentials!"""
		self.connection._tree = newtree
	
	async def do_trusts(self):
		"""Feteches gives back domain trusts"""
		try:
			async for entry, err in self.connection.get_all_trusts():
				if err is not None:
					raise err
				print(entry.get_line())
			
			return True
		except:
			traceback.print_exc()
			return False

	async def do_adduser(self, user_dn, password):
		"""Creates a new domain user with password"""
		try:
			_, err = await self.connection.create_user_dn(user_dn, password)
			if err is not None:
				raise err
			print('User added')
			return True
		except:
			traceback.print_exc()
			return False

	
	async def do_deluser(self, user_dn):
		"""Deletes the user! This action is irrecoverable (actually domain admins can do that but probably will shout with you)"""
		try:
			_, err = await self.connection.delete_user(user_dn)
			if err is not None:
				raise err
			print('Goodbye, Caroline.')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_changeuserpw(self, user_dn, newpass, oldpass = None):
		"""Changes user password, if you are admin then old pw doesnt need to be supplied"""
		try:
			_, err = await self.connection.change_password(user_dn, newpass, oldpass)
			if err is not None:
				raise err
			print('User password changed')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_unlockuser(self, user_dn):
		"""Unlock user by setting lockoutTime to 0"""
		try:
			_, err = await self.connection.unlock_user(user_dn)
			if err is not None:
				raise err
			print('User unlocked')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_enableuser(self, user_dn):
		"""Unlock user by flipping useraccountcontrol bits"""
		try:
			_, err = await self.connection.enable_user(user_dn)
			if err is not None:
				raise err
			print('User enabled')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_disableuser(self, user_dn):
		"""Unlock user by flipping useraccountcontrol bits"""
		try:
			_, err = await self.connection.disable_user(user_dn)
			if err is not None:
				raise err
			print('User disabled')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_addspn(self, user_dn, spn):
		"""Adds an SPN entry to the users account"""
		try:
			_, err = await self.connection.add_user_spn(user_dn, spn)
			if err is not None:
				raise err
			print('SPN added!')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_delspn(self, user_dn, spn):
		"""Removes an SPN entry to the users account"""
		try:
			_, err = await self.connection.del_user_spn(user_dn, spn)
			if err is not None:
				raise err
			print('SPN removed!')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_addhostname(self, user_dn, hostname):
		"""Adds additional hostname to computer account"""
		try:
			_, err = await self.connection.add_additional_hostname(user_dn, hostname)
			if err is not None:
				raise err
			print('Hostname added!')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_addusertogroup(self, user_dn, group_dn):
		"""Adds user to specified group. Both user and group must be in DN format!"""
		try:
			_, err = await self.connection.add_user_to_group(user_dn, group_dn)
			if err is not None:
				raise err
			print('User added to group!')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_deluserfromgroup(self, user_dn, group_dn):
		"""Removes user from specified group. Both user and group must be in DN format!"""
		try:
			_, err = await self.connection.del_user_from_group(user_dn, group_dn)
			if err is not None:
				raise err
			print('User added to group!')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_rootcas(self, to_print = True):
		"""Lists Root CA certificates"""
		try:
			cas = []
			async for ca, err in self.connection.list_root_cas():
				if err is not None:
					raise err
				cas.append(ca)
				if to_print is True:
					print(ca)
			return cas
		except:
			traceback.print_exc()
			return False

	async def do_ntcas(self, to_print = True):
		"""Lists NT CA certificates"""
		try:
			cas = []
			async for ca, err in self.connection.list_ntcas():
				if err is not None:
					raise err
				cas.append(ca)
				if to_print is True:
					print(ca)
			return cas
		except:
			traceback.print_exc()
			return False
	
	async def do_aiacas(self, to_print = True):
		"""Lists AIA CA certificates"""
		try:
			cas = []
			async for ca, err in self.connection.list_aiacas():
				if err is not None:
					raise err
				cas.append(ca)
				if to_print is True:
					print(ca)
			return cas
		except:
			traceback.print_exc()
			return False

	async def do_enrollmentservices(self, to_print=True):
		"""Lists AIA CA certificates"""
		try:
			services = []
			async for srv, err in self.connection.list_enrollment_services():
				if err is not None:
					raise err
				services.append(srv)
				if to_print is True:
					print(srv)
			return services
		except:
			traceback.print_exc()
			return False

	async def do_addcerttemplatenameflagaltname(self, certtemplatename, flags = None):
		"""Modifyies the msPKI-Certificate-Name-Flag value of the specified certificate template and enables ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME bit. If 'flags' is present then it will assign that value."""
		try:
			template = None
			async for template, err in self.connection.list_certificate_templates(certtemplatename):
				if err is not None:
					raise err
				break
			
			if template is None:
				raise Exception("Template could not be found!")
			
			template = typing.cast(MSADCertificateTemplate, template)
			if flags is not None:
				flags = int(flags)
			else:
				flags = int(CertificateNameFlag(template.Certificate_Name_Flag) | CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME)

			changes = {
				'msPKI-Certificate-Name-Flag' : [('replace', [flags])]
			}
	
			_, err = await self.connection.modify(template.distinguishedName, changes)
			if err is not None:
				raise err
			
			print('Modify OK!')
			return True


		except:
			traceback.print_exc()
			return False

	async def do_addenrollmentright(self, certtemplatename, user_dn):
		"""Grants enrollment rights to a user (by DN) for the specified certificate template."""
		try:
			user_sid, err = await self.connection.get_objectsid_for_dn(user_dn)
			if err is not None:
				raise err
			
			template = None
			async for template, err in self.connection.list_certificate_templates(certtemplatename):
				if err is not None:
					raise err
				break
			
			if template is None:
				raise Exception("Template could not be found!")
			template = typing.cast(MSADCertificateTemplate, template)
			new_sd = copy.deepcopy(template.nTSecurityDescriptor)
			ace = ACCESS_ALLOWED_OBJECT_ACE()
			ace.Sid = SID.from_string(user_sid)
			ace.ObjectType = GUID.from_string(EX_RIGHT_CERTIFICATE_ENROLLMENT)
			ace.AceFlags = AceFlags(0)
			ace.Mask = ADS_ACCESS_MASK.READ_PROP | ADS_ACCESS_MASK.WRITE_PROP | ADS_ACCESS_MASK.CONTROL_ACCESS
			ace.Flags = ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
			new_sd.Dacl.aces.append(ace)
			_, err = await self.connection.set_objectacl_by_dn(template.distinguishedName, new_sd.to_bytes(), flags=SDFlagsRequest.DACL_SECURITY_INFORMATION)
			if err is not None:
				raise err
			print('SD set sucessfully')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_certtemplates(self, name = None, to_print = True):
		"""Lists certificate templates"""
		try:
			services = await self.do_enrollmentservices(to_print=False)
			templates = []
			async for template, err in self.connection.list_certificate_templates(name):
				if err is not None:
					raise err
				
				lt = None
				if template.nTSecurityDescriptor is not None:
					lt, err = await self.connection.resolv_sd(template.nTSecurityDescriptor)
					if err is not None:
						raise err
				template.sid_lookup_table = lt
				for srv in services:
					if template.name in srv.certificateTemplates:
						template.enroll_services.append('%s\\%s' % (srv.dNSHostName, srv.name))

				templates.append(template)
				if to_print is True:
					print(template.prettyprint())

			return templates
		except:
			traceback.print_exc()
			return False

	async def do_sidresolv(self, sid, to_print = True):
		"""Returns the domain and username for SID"""
		try:
			domain, username, err = await self.connection.resolv_sid(sid)
			if err is not None:
				raise err
			res = '%s\\%s' % (domain, username)
			if to_print is True:
				print(res)
			return res
		except:
			traceback.print_exc()
			return False

	async def do_certify(self, cmd = None, username = None):
		"""ADCA security test"""
		try:
			es = await self.do_enrollmentservices(to_print=False)
			if es is False:
				raise Exception('Listing enrollment Services error! %s' % es)
			if es is None:
				raise Exception('No Enrollment Services present, stopping!')
			
			templates = await self.do_certtemplates(to_print=False)
			if templates is False:
				raise Exception('Listing templates error! %s' % es)
			
			if templates is None:
				raise Exception('No templates exists!')
			
			for enrollment in es:
				print(enrollment)
			
			if cmd is not None:
				if cmd.lower().startswith('vuln') is True:
					tokengroups = None
					if username is not None:
						tokengroups, err = await self.connection.get_tokengroups_user(username)
						if err is not None:
							raise err

					for template in templates:
						isvuln, reason = template.is_vulnerable(tokengroups)
						if isvuln is True:
							print(reason)
							print(template)
			else:
				for template in templates:
					print(template)

			return True
		except:
			traceback.print_exc()
			return False

	async def do_whoamiraw(self):
		"""Simple whoami"""
		try:
			res, err = await self.connection.whoami()
			if err is not None:
				raise err
			print(res)
		except:
			traceback.print_exc()
			return False
		
	async def do_whoami(self):
		"""Full whoami"""
		try:
			res, err = await self.connection.whoamifull()
			if err is not None:
				raise err
			
			for x in res:
				if isinstance(res[x], str) is True:
					print('%s: %s' % (x, res[x]))
				elif isinstance(res[x], dict) is True:
					for k in res[x]:
						print('Group: %s (%s)' % (k,'\\'.join(res[x][k])))
			return True
		except:
			traceback.print_exc()
			return False, None

	async def do_gmsa(self):
		"""Lists all managed service accounts (MSA). If user has permissions it retrieves the password as well"""
		try:
			print('---------------------------------------------')
			async for samaccountname, memberships, pwblob, err in self.connection.list_gmsa():
				if err is not None:
					raise err
				print('Username: %s' % samaccountname)
				allowed_machines = []
				if memberships is not None:
					for entry in memberships.Dacl.aces:
						if entry.AceType == ACEType.ACCESS_ALLOWED_ACE_TYPE:
							try:
								user = await self.do_sidresolv(entry.Sid, to_print=False)
								allowed_machines.append(user)
							except:
								allowed_machines.append(entry.Sid)
					for mname in allowed_machines:
						print('Allowed machine: %s' % mname)
				if pwblob is not None:
					print('Password: %s' % pwblob.CurrentPassword[:-2].hex())
					print('Password -NT-: %s' % pwblob.nt_hash)
				else:
					print('Password: <EMPTY>')
				print('---------------------------------------------')

		except:
			traceback.print_exc()
			return False

	async def do_test(self):
		"""testing, dontuse"""
		try:
			async for entry, err in self.connection.get_all_objectacl():
				if err is not None:
					raise err

				if entry.objectClass[-1] != 'user':
					print(entry.objectClass)

			return True
		except:
			traceback.print_exc()
			return False

	"""
	async def do_info(self):
		try:

		except Exception as e:
			traceback.print_exc()
	"""


async def amain(args):
	client = MSLDAPClientConsole(args.url)

	if len(args.commands) == 0:
		if args.no_interactive is True:
			print('Not starting interactive!')
			return
		await client.run()
	else:
		for command in args.commands:
			if command == 'i':
				await client.run()
				return
			cmd = shlex.split(command)
			res = await client._run_single_command(cmd[0], cmd[1:])
			if res is False:
				return

def main():
	import argparse
	parser = argparse.ArgumentParser(description='MS LDAP library')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
	parser.add_argument('-n', '--no-interactive', action='store_true')
	parser.add_argument('url', help='Connection string in URL format.')
	parser.add_argument('commands', nargs='*', help="Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")

	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	else:
		sockslogger.setLevel(logging.DEBUG)
		logger.setLevel(logging.DEBUG)
		logging.basicConfig(level=logging.DEBUG)

	asyncio.run(amain(args))

	

if __name__ == '__main__':
	main()
