#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import asyncio
import copy
import datetime
import importlib.util
import json
import logging
import os
import shlex
import sys
import traceback
import typing
import zipfile

from asyauth import logger as authlogger
from asyauth.common.credentials import UniCredential
from asysocks import logger as sockslogger
from asysocks.unicomm.common.target import UniTarget
from tabulate import tabulate
from tqdm import tqdm
from winacl.dtyp.ace import (ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE,
                             ACE_OBJECT_PRESENCE, ADS_ACCESS_MASK, AceFlags,
                             ACEType)
from winacl.dtyp.acl import ACL
from winacl.dtyp.guid import GUID
from winacl.dtyp.security_descriptor import SE_SACL, SECURITY_DESCRIPTOR
from winacl.dtyp.sid import SID

from msldap import logger
from msldap.commons.factory import LDAPConnectionFactory
from msldap.commons.plugin import MSLDAPConsolePlugin
from msldap.examples.utils.completers import PathCompleter
from msldap.external.aiocmd.aiocmd import aiocmd
from msldap.external.asciitree.asciitree import LeftAligned
from msldap.ldap_objects import (MSADGPO_ATTRS, MSADOU_ATTRS,
                                 MSADContainer_ATTRS, MSADDomainTrust_ATTRS,
                                 MSADGroup_ATTRS, MSADInfo_ATTRS,
                                 MSADMachine_ATTRS, MSADUser_TSV_ATTRS)
from msldap.ldap_objects.adcertificatetemplate import (
    EX_RIGHT_CERTIFICATE_ENROLLMENT, CertificateNameFlag,
    MSADCertificateTemplate)
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest


class MSLDAPClientConsole(aiocmd.PromptToolkitCmd):
	def __init__(self, url = None):
		aiocmd.PromptToolkitCmd.__init__(self, ignore_sigint=False) #Setting this to false, since True doesnt work on windows...
		self.conn_url = url
		if url is not None and isinstance(url, LDAPConnectionFactory) is False:
			self.conn_url = LDAPConnectionFactory.from_url(url)
		self.connection = None
		self.adinfo = None
		self.ldapinfo = None
		self.domain_name = None
		self.noisig = False
		self.nocb = False
		self._disable_channel_binding = False
		self._disable_signing = False
		self._null_channel_binding = False
		self.__current_dirs = {}
		self.__loaded_plugins = {}
		self._current_dn = None
		

	async def do_login(self, url = None):
		"""Performs connection and login"""
		try:			
			if self.conn_url is None and url is None:
				print('No URL was set, cant do logon')
			if url is not None and isinstance(url, LDAPConnectionFactory) is False:
				self.conn_url = LDAPConnectionFactory.from_url(url)

			logger.debug(self.conn_url.get_credential())
			logger.debug(self.conn_url.get_target())
			
			self.connection = self.conn_url.get_client()
			self.connection.keepalive = True
			self.connection._disable_channel_binding = self._disable_channel_binding
			self.connection._disable_signing = self._disable_signing
			self.connection._null_channel_binding = self._null_channel_binding
			_, err = await self.connection.connect()
			if err is not None:
				raise err
			logger.debug('BIND OK!')
			self.prompt = '[%s]> ' % (self.connection._tree,)
			self._current_dn = self.connection._tree
			if self.connection._con.is_anon is False:
				await self.do_cd(self._current_dn)
			else:
				print('Anonymous connection. Most functionalities will not work!')
			
			return True
		except:
			traceback.print_exc()
			return False
		
	async def do_nosig(self):
		"""Disables signing"""
		self._disable_signing = True
		return True
	
	async def do_nocb(self):
		"""Disables channel binding"""
		self._disable_channel_binding = True
		return True
	
	async def do_nullcb(self):
		"""Sets incorrect channel binding data"""
		self._null_channel_binding = True
		return True

	async def do_ldapinfo(self, show = True):
		"""Prints detailed LDAP connection info (DSA)"""
		try:
			if self.ldapinfo is None:
				self.ldapinfo = self.connection.get_server_info()
			if show is True:
				for k in self.ldapinfo:
					if isinstance(self.ldapinfo[k], list):
						for item in self.ldapinfo[k]:
							print('%s : %s' % (k, item))
					else:
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
		zip_filename = 'dump_%s.zip' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
		
		try:
			await self.do_adinfo(False)
			await self.do_ldapinfo(False)

			tname = 'domain_%s' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			users_filename = '%s.tsv' % tname
			
			
			try:
				with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
					f.write('\t'.join(MSADInfo_ATTRS)+'\r\n')
					adinfo, err = await self.connection.get_ad_info()
					if err is not None:
						raise err
					f.write('\t'.join(adinfo.get_row(MSADInfo_ATTRS))+'\r\n')
				print('Adinfo was written to %s' % users_filename)
				with zipfile.ZipFile(zip_filename, 'a', compression=zipfile.ZIP_BZIP2) as dz:
					dz.write(users_filename, arcname = users_filename)
			finally:
				try:
					os.remove(users_filename)
				except:
					pass

			tname = 'schema_%s' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			users_filename = '%s.json' % tname

			try:
				pbar = tqdm(desc = 'Writing schema to file %s' % users_filename)
				schema = {}
				with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
					async for user, err in self.connection.get_all_schemaentry(['name', 'schemaidguid']):
						if err is not None:
							raise err
						pbar.update()
						schema[user.name.lower()] = str(user.schemaIDGUID)
						
					json.dump(schema, f)

					print('Schema dump was written to %s' % users_filename)
					pbar.close()
					with zipfile.ZipFile(zip_filename, 'a', compression=zipfile.ZIP_BZIP2) as dz:
						dz.write(users_filename, arcname = users_filename)
			finally:
				try:
					os.remove(users_filename)
				except:
					pass
			
			tname = 'trusts_%s' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			users_filename = '%s.tsv' % tname

			try:
				pbar = tqdm(desc = 'Writing trusts to file %s' % users_filename)
				with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
					f.write('\t'.join(MSADDomainTrust_ATTRS)+'\r\n')
					async for user, err in self.connection.get_all_trusts():
						if err is not None:
							raise err
						pbar.update()
						f.write('\t'.join(user.get_row(MSADDomainTrust_ATTRS))+'\r\n')

				print('Trust dump was written to %s' % users_filename)
				pbar.close()
				with zipfile.ZipFile(zip_filename, 'a', compression=zipfile.ZIP_BZIP2) as dz:
					dz.write(users_filename, arcname = users_filename)
			finally:
				try:
					os.remove(users_filename)
				except:
					pass
				

			tname = 'users_%s' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			users_filename = '%s.tsv' % tname
				
			try:	
				pbar = tqdm(desc = 'Writing users to file %s' % users_filename)
				
				with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
					f.write('\t'.join(MSADUser_TSV_ATTRS)+'\r\n')
					async for user, err in self.connection.get_all_users():
						if err is not None:
							raise err
						pbar.update()
						f.write('\t'.join(user.get_row(MSADUser_TSV_ATTRS))+'\r\n')
				print('Users dump was written to %s' % users_filename)
				pbar.close()
				with zipfile.ZipFile(zip_filename, 'a', compression=zipfile.ZIP_BZIP2) as dz:
					dz.write(users_filename, arcname = users_filename)
			finally:
				try:
					os.remove(users_filename)
				except:
					pass
				
			tname = 'computers_%s' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			users_filename = '%s.tsv' % tname

			try:
				pbar = tqdm(desc = 'Writing computers to file %s' % users_filename)
				with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
					f.write('\t'.join(MSADMachine_ATTRS)+'\r\n')
					async for user, err in self.connection.get_all_machines():
						if err is not None:
							raise err
						pbar.update()
						f.write('\t'.join(user.get_row(MSADMachine_ATTRS))+'\r\n')
				print('Computer dump was written to %s' % users_filename)
				pbar.close()
				with zipfile.ZipFile(zip_filename, 'a', compression=zipfile.ZIP_BZIP2) as dz:
					dz.write(users_filename, arcname = users_filename)
			finally:
				try:
					os.remove(users_filename)
				except:
					pass
				
			tname = 'groups_%s' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			users_filename = '%s.tsv' % tname
			try:
				pbar = tqdm(desc = 'Writing groups to file %s' % users_filename)
				with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
					f.write('\t'.join(MSADGroup_ATTRS)+'\r\n')
					async for user, err in self.connection.get_all_groups():
						if err is not None:
							raise err
						pbar.update()
						f.write('\t'.join(user.get_row(MSADGroup_ATTRS))+'\r\n')
				print('Group dump was written to %s' % users_filename)
				pbar.close()
				with zipfile.ZipFile(zip_filename, 'a', compression=zipfile.ZIP_BZIP2) as dz:
					dz.write(users_filename, arcname = users_filename)
			finally:
				try:
					os.remove(users_filename)
				except:
					pass
				
			tname = 'ous_%s' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			users_filename = '%s.tsv' % tname
			try:
				pbar = tqdm(desc = 'Writing OUs to file %s' % users_filename)
				with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
					f.write('\t'.join(MSADOU_ATTRS)+'\r\n')
					async for user, err in self.connection.get_all_ous():
						if err is not None:
							raise err
						pbar.update()
						f.write('\t'.join(user.get_row(MSADOU_ATTRS))+'\r\n')
				print('OU dump was written to %s' % users_filename)
				pbar.close()
				with zipfile.ZipFile(zip_filename, 'a', compression=zipfile.ZIP_BZIP2) as dz:
					dz.write(users_filename, arcname = users_filename)
			finally:
				try:
					os.remove(users_filename)
				except:
					pass

				
			tname = 'containers_%s' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			users_filename = '%s.tsv' % tname
			try:
				pbar = tqdm(desc = 'Writing Containers to file %s' % users_filename)
				with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
					f.write('\t'.join(MSADContainer_ATTRS)+'\r\n')
					async for user, err in self.connection.get_all_containers():
						if err is not None:
							raise err
						pbar.update()
						f.write('\t'.join(user.get_row(MSADContainer_ATTRS))+'\r\n')
				print('Container dump was written to %s' % users_filename)
				pbar.close()
				with zipfile.ZipFile(zip_filename, 'a', compression=zipfile.ZIP_BZIP2) as dz:
					dz.write(users_filename, arcname = users_filename)
			finally:
				try:
					os.remove(users_filename)
				except:
					pass

			tname = 'gpos_%s' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			users_filename = '%s.tsv' % tname
			try:
				pbar = tqdm(desc = 'Writing GPOs to file %s' % users_filename)
				with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
					f.write('\t'.join(MSADOU_ATTRS)+'\r\n')
					async for user, err in self.connection.get_all_gpos():
						if err is not None:
							raise err
						pbar.update()
						f.write('\t'.join(user.get_row(MSADGPO_ATTRS))+'\r\n')
				print('GPO dump was written to %s' % users_filename)
				pbar.close()
				with zipfile.ZipFile(zip_filename, 'a', compression=zipfile.ZIP_BZIP2) as dz:
					dz.write(users_filename, arcname = users_filename)
			finally:
				try:
					os.remove(users_filename)
				except:
					pass


			try:
				dns_filename = 'dns_%s.tsv' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
				pbar = tqdm(desc = 'Writing DNS records to file %s' % dns_filename)
				with open(dns_filename, 'w', newline='', encoding = 'utf8') as f:
					async for zonedn, name, dnsrecod, err in self.connection.dnsentries():
						if err is not None:
							raise err			
						dnsdataobj = dnsrecod.get_formatted()
						line = '\t'.join([zonedn, name, dnsrecod.Type.name, dnsdataobj.to_line()])
						f.write(line + '\r\n')
						pbar.update(1)
				print('DNS dump was written to %s' % dns_filename)
				pbar.close()
				with zipfile.ZipFile(zip_filename, 'a', compression=zipfile.ZIP_BZIP2) as dz:
					dz.write(dns_filename, arcname = dns_filename)
			finally:
				try:
					os.remove(dns_filename)
				except:
					pass

			
			print('All dumps were written to %s' % zip_filename)
			
			return True
		except:			
			traceback.print_exc()
			return False

	def get_current_dirs(self):
		if self.__current_dirs is None:
			return []
		curdirs = []
		for dirname in self.__current_dirs:
			if dirname.find(' ') != -1:
				dirname = "'%s'" % dirname
			curdirs.append(dirname)
		return curdirs

	def _cd_completions(self):
		return PathCompleter(get_current_dirs = self.get_current_dirs)
	
	async def do_cd(self, path):
		"""Change current work directory"""
		original_path = self._current_dn
		try:
			if path == '.':
				self._current_dn = original_path
			elif path == '..':
				#this is not a good solution but I don't have to to write a proper DN parser...
				#TODO: implement DN parsing
				self._current_dn = original_path[original_path.find(',')+1:]
			else:
				self._current_dn = path
			if path in self.__current_dirs:
				self._current_dn = self.__current_dirs[path]
			tree_data = await self.connection.get_tree_plot(self._current_dn, level=1)
			root = list(tree_data.keys())[0]
			self.__current_dirs = {}
			for dn in tree_data[root].keys():
				lookup_dn = dn[:-(len(self._current_dn)+1)]
				self.__current_dirs[lookup_dn] = dn
			self.prompt = '[%s]> ' % (self._current_dn,)
			return True
		except Exception as e:
			print('Change directory error! %s' % e)
			self._current_dn = original_path
			self.prompt = '[%s]> ' % (self._current_dn,)
			return False

	async def do_rm(self, subdn, confirm = 'NO'):
		"""Remove an object from the current DN"""
		dn = '%s,%s' % (subdn, self._current_dn)
		res = await self.do_delete(dn, confirm)
		if res is True:
			await self.do_cd('.')
		return res

	async def do_delete(self, dn, confirm = 'NO'):
		"""Remove an object identified by its DN"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			if self.connection._con.is_anon is True:
				print('Anonymous connection. Most functionalities will not work!')
				return False
			
			print('This will delete the following object: %s' % dn)
			if confirm.upper() != 'YES':
				print('As a safety measure, you have to confirm the deletion by typing YES in all caps after the DN to be deleted!')
				print('Example: "delete %s YES"' % dn)
				print('Not confirmed! Aborting!')
				return False
			_, err = await self.connection.delete(dn)
			if err is not None:
				raise err
			print('Delete OK!')
			return True
		except:
			traceback.print_exc()
			return False

	async def do_ls(self, fullpath = False):
		"""Print objects in current work directory"""
		for dn in self.__current_dirs:
			entry = dn
			if fullpath is not False:
				entry = self.__current_dirs[dn]
			print(entry)
		return True

	async def do_cat(self, attributes="*", dn=''):
		"""Print attributes of object. Without arguments it will cat the current DN"""
		attributes = attributes.split(",")
		if dn == '':
			dn = self._current_dn
		async for entry, err in self.connection.pagedsearch(query="(distinguishedName=%s)"%dn, attributes=attributes, tree=dn):
			if err is not None:
				raise err
			for attr in entry["attributes"]:
				if type(entry["attributes"][attr]) == list:
					for i, val in enumerate(entry["attributes"][attr]):
						print("%s [%s]: %s" % (attr, i, val))
				else:
					val = entry["attributes"][attr]
					print("%s: %s" % (attr, val))
		return True

	async def do_modify(self, dn, attribute, value):
		"""Modify an attribute of object. Only works with string data types!"""
		changes = {
			attribute : [('replace', value)]
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
		
	async def do_sam2dn(self, sAMAccountName):
		"""Fetches the DN of an object based on the sAMAccountName"""
		dn, err = await self.connection.sam2dn(sAMAccountName)
		if err is not None:
			raise err
		print(dn)
		return True
	
	async def do_sid2dn(self, sid):
		"""Fetches the DN of an object based on the objectSid"""
		dn, err = await self.connection.sid2dn(sid)
		if err is not None:
			raise err
		print(dn)
		return True
		
	async def do_dn2sid(self, dn):
		"""Fetches the objectSid of an object based on the DN"""
		sid, err = await self.connection.dn2sid(dn)
		if err is not None:
			raise err
		print(sid)
		return True
	
	async def do_dn2sam(self, dn):
		"""Fetches the sAMAccountName of an object based on the DN"""
		sam, err = await self.connection.dn2sam(dn)
		if err is not None:
			raise err
		print(sam)
		return True
	
	async def do_dadms(self):
		"""Lists all members of the domain administrators group"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)

			dn, err = await self.connection.sid2dn(self.adinfo.objectSid + '-512')
			if err is not None:
				raise err
			
			async for obj, err in self.connection.get_group_members(dn, recursive=True):
				if err is not None:
					raise err
				print(obj.distinguishedName)			
			return True
		except:
			traceback.print_exc()
			return False
	
	async def do_groupmembers(self, dn, recursive = True):
		"""Returns all member users in a group specified by DN"""
		try:
			if recursive is not False or recursive != '0':
				recursive = True
			async for obj, err in self.connection.get_group_members(dn, recursive=recursive):
				if err is not None:
					raise err
				print(obj.distinguishedName)
			return True
		except Exception as e:
			traceback.print_exc()
			return False	

	async def do_addallowedtoactonbehalfofotheridentity(self, target_dn, other_identity_sid):
		"""Adds a SID to the msDS-AllowedToActOnBehalfOfOtherIdentity protperty of target_dn"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
	
			try:
				computer_sid = SID.from_string(other_identity_sid)
			except:
				print('Incorrect SID!')
				return False, Exception('Incorrect SID')
	
	
			query = '(distinguishedName=%s)' % target_dn
			async for entry, err in self.connection.pagedsearch(query, ['msDS-AllowedToActOnBehalfOfOtherIdentity', 'objectSid']):
				if err is not None:
					raise err
				
				if 'msDS-AllowedToActOnBehalfOfOtherIdentity' not in entry['attributes']:
					print('Attribute does not exist on the current object, crafing new SD')					
					target_sd = SECURITY_DESCRIPTOR()
					target_sd.Control = SE_SACL.SE_DACL_PRESENT | SE_SACL.SE_SELF_RELATIVE
					target_sd.Owner = SID.from_string('S-1-5-32-544')
					target_sd.Group = None
					target_sd.Sacl = None
					target_sd.Dacl = ACL()
					target_sd.Dacl.AclRevision = 4
					target_sd.Dacl.Sbz1 = 0
					target_sd.Dacl.Sbz2 = 0

				else:
					target_sd = SECURITY_DESCRIPTOR.from_bytes(entry['attributes']['msDS-AllowedToActOnBehalfOfOtherIdentity'])
				
				break
			else:
				print('Target DN not found!')
				return False, Exception('Target DN not found!')
			
			# checking if account is already there
			for ace in target_sd.Dacl.aces:
				if ace.Sid == computer_sid:
					print('Account is already there!')
					return False, Exception('Account is already there!')

			print('Constructing new ACE')
			ace = ACCESS_ALLOWED_ACE()
			ace.AceFlags = 0
			#ace.AceSize = 0
			ace.Mask = 983551
			ace.Sid = computer_sid

			new_sd = copy.deepcopy(target_sd)
			new_sd.Dacl.aces.append(ace)

			changes = {
				'msDS-AllowedToActOnBehalfOfOtherIdentity' : [('replace', new_sd.to_bytes())]
			}
			_, err = await self.connection.modify(target_dn, changes)
			if err is not None:
				raise err
				
			print('Change OK!')
		except:
			traceback.print_exc()

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
			
	async def do_getsd(self, dn, opts=' '):
		"""Feteches security info for a given DN"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			sec_info, err = await self.connection.get_objectacl_by_dn(dn)
			if err is not None:
				raise err
			sd = SECURITY_DESCRIPTOR.from_bytes(sec_info)
			domain, username, err = await self.connection.resolv_sid(sd.Owner.to_sddl())
			print("OWNER: %s\\%s" % (domain, username))
			domain, username, err = await self.connection.resolv_sid(sd.Group.to_sddl())
			print("GROUP: %s\\%s" % (domain, username))
			out = []
			for ace in sd.Dacl.aces:
				if SID.wellknown_sid_lookup(ace.Sid.to_sddl()):
					canonical = SID.wellknown_sid_lookup(ace.Sid.to_sddl())
				else:
					domain, username, err = await self.connection.resolv_sid(ace.Sid.to_sddl())
					if username != '???':
						canonical = '%s\\%s' % (domain, username)
					else:
						canonical = ace.Sid.to_sddl()
				if opts[0] == 'g':
					row = []
					for line in str(ace).split("\n"):
						row.append(line.split(":")[-1])
					out.append([canonical] + row)
				elif opts[0] == 'p':
					for line in str(ace).split("\n"):
						out.append([canonical, line])
			if opts[0] == 'g':
				print(tabulate(out, headers=["Who","Type","Flags","SID","Mask","ObjectType","InheritedObjectType","ObjectFlags","ACType",""]))
			elif opts[0] == 'p':
				print(tabulate(out, headers=["Who","ACE"]))
			else:
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
			# trying to get the old version LAPS
			async for entry, err in self.connection.get_all_laps():
				if err is not None:
					raise err
				if 'ms-Mcs-AdmPwd' in entry['attributes']:
					pwd = entry['attributes']['ms-Mcs-AdmPwd']
					print('%s : %s' % (entry['attributes']['cn'], pwd))
			
			# now trying to get the new version LAPS
			async for entry, err in self.connection.get_all_laps_windows():
				if err is not None:
					raise err
				
				if 'msLAPS-Password' in entry['attributes']:
					pwd = entry['attributes']['msLAPS-Password']
					print('%s : %s' % (entry['attributes']['cn'], pwd))
					
					
				if 'msLAPS-EncryptedPassword' in entry['attributes']:
					pwd = entry['attributes']['msLAPS-EncryptedPassword']
					print('%s : %s' % (entry['attributes']['cn'], pwd.hex()))

				if 'msLAPS-EncryptedPasswordHistory' in entry['attributes']:
					pwd = entry['attributes']['msLAPS-EncryptedPasswordHistory']
					print('%s : %s' % (entry['attributes']['cn'], pwd))
				
				if 'msLAPS-EncryptedDSRMPassword' in entry['attributes']:
					pwd = entry['attributes']['msLAPS-EncryptedDSRMPassword']
					print('%s : %s' % (entry['attributes']['cn'], pwd))
				
				if 'msLAPS-EncryptedDSRMPasswordHistory' in entry['attributes']:
					pwd = entry['attributes']['msLAPS-EncryptedDSRMPasswordHistory']
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
				group_sids.append(group_sid)
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
		"""Changes the LDAP TREE for future queries. MUST be DN format eg. 'DC=test,DC=corp'"""
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
			print('User removed from group!')
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
				'msPKI-Certificate-Name-Flag' : [('replace', flags)]
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

	async def do_certify2(self, username=None):
		"""ADCA security test - new version"""
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
			
			results = []
			tokengroups = None
			if username is not None:
				tokengroups, err = await self.connection.get_tokengroups_user(username)
				if err is not None:
					raise err
			else:
				res, err = await self.connection.whoamifull()
				if err is not None:
					raise err
				tokengroups = res['tokengroups']

			for template in templates:
				res = template.is_vulnerable2(tokengroups)
				if len(res) == 0:
					continue
						
				es = template.enrollment_services
				is_enabled = True
				if len(es) == 0:
					es = [(None, None)]
					is_enabled = False
				
				for hostname, service in es:
					t =  'Template Name: %s\n' % template.name
					t += 'Enrollment Service Name: %s\n' % service
					t += 'Enrollment Service Host: %s\n' % hostname
					t += 'Enabled: %s\n' % is_enabled
					t += 'Vulnerabilities:\n'
					for r in res:
						t += '\t%s - %s\n' % (r, res[r].get('Reason', ''))
					print(t)

					entry = {
						'enabled': is_enabled,
						'template' : template.name,
						'service' : service,
						'hostname' : hostname,
						'vulns' : res
					}
					results.append(entry)

			return results
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
	
	async def do_genschema(self):
		"""Generates schema data. This will take a long time."""
		try:
			import json
			attributes = {}
			testattr = {}
			async for attribute, err in self.connection.get_all_schemaentry():
				if err is not None:
					raise err
				attributes[attribute.lDAPDisplayName] = attribute.to_dict()
				try:
					if attribute.isSingleValued is not None:
						testattr[attribute.lDAPDisplayName] = attribute.get_type()
				except:
					print(print(attribute.to_dict()))
			with open('adschema.json','w') as f:
				json.dump(attributes,f)
			with open('adschema.py', 'w', newline = '') as f:
				f.write('LDAP_WELL_KNOWN_ATTRS = {\r\n')
				line = ''
				for attrname in testattr:
					line += '\t"%s" : %s,\r\n' % (attrname, testattr[attrname])
				f.write(line)
				f.write('}')
		except:
			traceback.print_exc()
			return False
		
	async def do_addcomputer(self, computername=None, password=None):
		"""Adds a new computer account"""
		try:
			computer, password, err = await self.connection.add_computer(computername, password)
			if err is not None:
				raise err
			print(computer)
			print('sAMAccountName: %s' % computer.sAMAccountName)
			print('Password: %s' % password)
		except:
			traceback.print_exc()
			return False
		
	async def do_changesamaccountname(self, dn, newname):
		"""Changes the sAMAccountName of a given DN"""
		try:
			err = await self.connection.change_samaccountname(dn, newname)
			if err is not None:
				raise err
			print('OK')
		except:
			traceback.print_exc()
			return False
	
	async def do_unconstrained(self):
		"""Lists all unconstrained delegation objects"""
		try:
			print('Objects with Unconstrained Delegation set:')
			async for entry, err in self.connection.get_unconstrained_machines():
				if err is not None:
					raise err
				print(entry)
			
			async for entry, err in self.connection.get_unconstrained_users():
				if err is not None:
					raise err
				print(entry)
			

		except:
			traceback.print_exc()
			return False
	
	async def do_constrained(self):
		"""Lists all constrained delegation objects"""
		try:
			print('Objects with Constrained Delegation set:')
			async for entry, err in self.connection.get_all_constrained():
				if err is not None:
					raise err
				sname = entry.get('sAMAccountName', '')
				for x in entry.get('msDS-AllowedToDelegateTo', []):
					print('%s -> %s' % (sname, x))
			
		except:
			traceback.print_exc()
			return False
		
	async def do_s4u2proxy(self):
		"""Lists all S4U2Proxy objects"""
		try:
			print('S4U2Proxy set:')
			async for entry, err in self.connection.get_all_s4u2proxy():
				if err is not None:
					raise err
				print(entry)
			
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

	async def do_dnszones(self, to_print_props = False):
		"""Lists all DNS zones"""
		try:
			async for entry, props, err in self.connection.dnslistzones():
				if err is not None:
					raise err

				print(entry)

				if to_print_props is False:
					continue

				for prop in props:
					print(" ", prop)

				print()

			return True
		except:
			traceback.print_exc()
			return False

	async def do_dnsdump(self, zone = None):
		try:
			if zone == '':
				zone = None
			
			dns_filename = 'dns_%s.tsv' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			pbar = tqdm(desc = 'Writing DNS records to file %s' % dns_filename)
			with open(dns_filename, 'w', newline='', encoding = 'utf8') as f:
				async for zonedn, name, dnsrecod, err in self.connection.dnsentries(zone):
					if err is not None:
						raise err
					
					dnsdataobj = dnsrecod.get_formatted()
					line = '\t'.join([zonedn, name, dnsrecod.Type.name, dnsdataobj.to_line()])

					f.write(line + '\r\n')
					pbar.update(1)

			return True
		except Exception as e:
			traceback.print_exc()
			return False
	
	async def do_pre2000(self):
		"""Lists potentially abusable machine accounts created with pre windows-2000 flag"""
		try:
			query = '(&(userAccountControl=4128)(logonCount=0))'
			async for entry, err in self.connection.pagedsearch(query, attributes=['sAMAccountName']):
				if err is not None:
					raise err

				print(entry)
			return True
		except:
			traceback.print_exc()
			return False

	async def do_plugin(self, pluginpath, runargs = None):
		"""Loads a plugin and runs it"""
		try:
			if pluginpath not in self.__loaded_plugins:
				spec = importlib.util.spec_from_file_location("plugin_module_%s" % len(self.__loaded_plugins), pluginpath)
				plugin_module = importlib.util.module_from_spec(spec)
				sys.modules["plugin_module_%s" % len(self.__loaded_plugins)] = plugin_module
				spec.loader.exec_module(plugin_module)
				self.__loaded_plugins[pluginpath] = plugin_module
			else:
				plugin_module = self.__loaded_plugins[pluginpath]
			# Find the MSLDAPConsolePlugin subclass
			for item in dir(plugin_module):
				obj = getattr(plugin_module, item)
				if isinstance(obj, type) and issubclass(obj, MSLDAPConsolePlugin) and obj is not MSLDAPConsolePlugin:
					plugin_instance = obj(self, self.connection)
					return await plugin_instance.run(runargs)
			else:
				print('No plugin class found in that module! Please make sure you have a class that inherits from MSLDAPConsolePlugin!')
				return False
		except:
			traceback.print_exc()
			return False


async def amain(args):
	import platform
	
	if args.url is not None:
		client = MSLDAPClientConsole(args.url)
	else:
		if platform.system() != 'Windows':
			raise Exception('This function only works on Windows systems!')
		from asyauth.common.credentials import UniCredential
		from winacl.functions.highlevel import get_logon_info

		from msldap.commons.target import MSLDAPTarget, UniProto
		cred = UniCredential.get_sspi(args.authtype)
		userinfo = get_logon_info()
		if args.target is not None:
			ip = args.target
			if args.target.find(':') is not None:
				ip, port = args.target.split(':')
			target = MSLDAPTarget(ip=ip, port=port)
		else:
			if userinfo['logonserver'] is not None and len(userinfo['logonserver']) > 0:
				target = MSLDAPTarget(
					ip=userinfo['logonserver'], 
					hostname = userinfo['logonserver'], 
					dc_ip=userinfo['logonserver'],
					domain=userinfo['dnsdomainname'],
				)
				if args.ldaps is True:
					target = MSLDAPTarget(
						ip=userinfo['logonserver'], 
						hostname = userinfo['logonserver'],
						protocol = UniProto.CLIENT_SSL_TCP,
						port = 636,
						dc_ip=userinfo['logonserver'],
						domain=userinfo['dnsdomainname'],
					)
				
			else:
				raise Exception('Couldnt find logonserver! Are you connected to a domain?')
		factory = LDAPConnectionFactory(cred, target)
		client = MSLDAPClientConsole(factory)

	if len(args.commands) == 0:
		if args.no_interactive is True:
			print('Not starting interactive!')
			return
		res = await client._run_single_command('login', [])
		if res is False:
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
	import platform
	protocols = """LDAP : basic LDAP protocol
	LDAPS: LDAP over SSL
	GC   : Global Catalog
	GCS  : Global Catalog over SSL"""
	authprotos = """ntlm     : SASL NTLM authentication
	kerberos : SASL Kerberos authentication
	sspi-ntlm: SSPI authentication using NTLM (Windows only, uses SASL)
	sspi-kerberos: SSPI authentication using Kerberos (Windows only, uses SASL)
	simple   : LDAP SIMPLE authentication
	plain    : PLAIN authentication
	sicily   : SICILY authentication
	ssl      : Authenticate with SSL certificate
	none     : No authentication, anonymous bind
	"""
	usage = UniCredential.get_help(protocols, authprotos, '')
	usage += UniTarget.get_help()
	usage += """
Examples:
All of the following examples show LDAP auth to the DC of TEST.corp domain at Win2019AD.test.corp(10.10.10.2)
Kerberos authentication needs the FQDN of the DC, so we use the 'dc' parameter to specify the DC.

Anonymous BIND:
	ldap://10.10.10.2
Username and password authentication using NTLM over plaintext LDAP:
	ldap+ntlm-password://TEST\\victim:password@10.10.10.2
Username and password authentication using NTLM over SSL/TLS:
	ldaps+ntlm-password://TEST\\victim:password@10.10.10.2
Username and password authentication using Kerberos over plaintext LDAP:
	ldap+kerberos-password://TEST\\victim:password@<hostname>/?dc=10.10.10.2
Username and password authentication using Kerberos over SSL/TLS:
	ldaps+kerberos-password://TEST\\victim:password@<hostname>/?dc=10.10.10.2
NTLM authentication using the NT hash over plaintext LDAP:
	ldap+ntlm-nt://TEST\\victim:<NThash>@10.10.10.2
Kerberos authentication using the RC4 key over plaintext LDAP:
	ldap+kerberos-rc4://TEST\\victim:<RC4key>@<hostname>/?dc=10.10.10.2
SICILY authentication using the NT hash over plaintext LDAP:
	ldap+sicily-nt://TEST\\victim:<NThash>@10.10.10.2
Kerberos authentication using AES key over plaintext LDAP:
	ldap+kerberos-aes://TEST\\victim:<AESkey>@<hostname>/?dc=10.10.10.2
Kerberos authentication using CCACHE file over plaintext LDAP:
	ldap+kerberos-ccache://TEST\\victim:<CCACHEfile>@<hostname>/?dc=10.10.10.2
Kerberos authentication using keytab file over plaintext LDAP:
	ldap+kerberos-keytab://TEST\\victim:<KEYTABfile>@<hostname>/?dc=10.10.10.2
Kerberos authentication using P12 or PFX file over plaintext LDAP (notice that keyfile password is at the 'password' filed):
	ldap+kerberos-pfx://TEST\\victim:admin@<hostname>/?dc=10.10.10.2&keydata=<P12file>
SSL authentication using P12 or PFX file over plaintext LDAP, automatically performs STARTTLS:
	ldap+ssl://10.10.10.2/?sslcert=<P12file>&sslpassword=<P12password>'
SSL authentication using P12 or PFX file over SSL/TLS LDAP:
	ldaps+ssl://10.10.10.2/?sslcert=<P12file>&sslpassword=<P12password>'
"""
	parser = argparse.ArgumentParser(description='MS LDAP library', usage = usage)
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
	parser.add_argument('-n', '--no-interactive', action='store_true')
	if platform.system() == 'Windows':
		group = parser.add_argument_group(title='URL')
		group.add_argument('--url', help='Connection string in URL format.')
		group2 = parser.add_argument_group(title='Without URL')
		group2.add_argument('--authtype', default='ntlm', help='Connection string in URL format.')
		group2.add_argument('--target', help='Address of LDAP server.')
		group2.add_argument('--ldaps', action='store_true', help='Use LDAPS')

	else:
		parser.add_argument('url', help='Connection string in URL format.')
	parser.add_argument('commands', nargs='*', help="Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")

	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	else:
		sockslogger.setLevel(logging.DEBUG)
		logger.setLevel(logging.DEBUG)
		authlogger.setLevel(logging.DEBUG)
		logging.basicConfig(level=logging.DEBUG)


	asyncio.run(amain(args))

	

if __name__ == '__main__':
	main()
