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

from msldap.external.aiocmd.aiocmd import aiocmd
from msldap.external.asciitree.asciitree import LeftAligned
from tqdm import tqdm

from msldap import logger
from asysocks import logger as sockslogger
from msldap.client import MSLDAPClient
from msldap.commons.url import MSLDAPURLDecoder
from msldap.ldap_objects import MSADUser, MSADMachine, MSADUser_TSV_ATTRS

from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR


class MSLDAPClientConsole(aiocmd.PromptToolkitCmd):
	def __init__(self, url = None):
		aiocmd.PromptToolkitCmd.__init__(self, ignore_sigint=False) #Setting this to false, since True doesnt work on windows...
		self.conn_url = None
		if url is not None:
			self.conn_url = MSLDAPURLDecoder(url)
		self.connection = None
		self.adinfo = None
		self.ldapinfo = None

	async def do_login(self, url = None):
		"""Performs connection and login"""
		try:			
			if self.conn_url is None and url is None:
				print('Not url was set, cant do logon')
			if url is not None:
				self.conn_url = MSLDAPURLDecoder(url)

			logger.debug(self.conn_url.get_credential())
			logger.debug(self.conn_url.get_target())
			
			
			self.connection = self.conn_url.get_client()
			_, err = await self.connection.connect()
			if err is not None:
				raise err
			
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
				print(self.ldapinfo)
			return True
		except:
			traceback.print_exc()
			return False

	async def do_adinfo(self, show = True):
		"""Prints detailed Active Driectory info"""
		try:
			if self.adinfo is None:
				self.adinfo = self.connection._ldapinfo
			if show is True:
				print(self.adinfo)
		except:
			traceback.print_exc()

	async def do_spns(self):
		"""Fetches kerberoastable user accounts"""
		try:
			await self.do_ldapinfo(False)
			async for user, err in self.connection.get_all_service_users():
				if err is not None:
					raise err
				print(user.sAMAccountName)
		except:
			traceback.print_exc()
	
	async def do_asrep(self):
		"""Fetches ASREP-roastable user accounts"""
		try:
			await self.do_ldapinfo(False)
			async for user, err in self.connection.get_all_knoreq_users():
				if err is not None:
					raise err
				print(user.sAMAccountName)
		except:
			traceback.print_exc()


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
					f.write('\t'.join(user.get_row(MSADUser_TSV_ATTRS)))
			print('Users dump was written to %s' % users_filename)
			
			users_filename = 'computers_%s.tsv' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
			pbar = tqdm(desc = 'Writing computers to file %s' % users_filename)
			with open(users_filename, 'w', newline='', encoding = 'utf8') as f:
				async for user, err in self.connection.get_all_machines():
					if err is not None:
						raise err
					pbar.update()
					f.write('\t'.join(user.get_row(MSADUser_TSV_ATTRS)))
			print('Computer dump was written to %s' % users_filename)
		except:
			traceback.print_exc()
		
	async def do_query(self, query, attributes = None):
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
		except:
			traceback.print_exc()

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


		except:
			traceback.print_exc()

	async def do_user(self, samaccountname):
		"""Feteches a user object based on the sAMAccountName of the user"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			user, err = await self.connection.get_user(samaccountname)
			if err is not None:
				raise err
			if user is None:
				print('User not found!')
			else:
				print(user)
		except:
			traceback.print_exc()

	async def do_acl(self, dn):
		"""Feteches security info for a given DN"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			sec_info, err = await self.connection.get_objectacl_by_dn(dn)
			if err is not None:
				raise err
			print(str(SECURITY_DESCRIPTOR.from_bytes(sec_info)))
		except:
			traceback.print_exc()

	async def do_gpos(self):
		"""Feteches security info for a given DN"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			async for gpo, err in self.connection.get_all_gpos():
				if err is not None:
					raise err
				print(gpo)
		except:
			traceback.print_exc()

	async def do_laps(self):
		"""Feteches all laps passwords"""
		try:
			async for entry, err in self.connection.get_all_laps():
				if err is not None:
					raise err
				pwd = '<MISSING>'
				if 'ms-mcs-AdmPwd' in entry['attributes']:
					pwd = entry['attributes']['ms-mcs-AdmPwd']
				print('%s : %s' % (entry['attributes']['cn'], pwd))
		except:
			traceback.print_exc()

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
		except Exception as e:
			print(e)
			traceback.print_exc()

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
		except:
			traceback.print_exc()

	async def do_adduser(self, username, password):
		"""Creates a new domain user with password"""
		try:
			_, err = await self.connection.create_user(username, password)
			if err is not None:
				raise err
			print('User added')
		except:
			traceback.print_exc()

	
	async def do_deluser(self, user_dn):
		"""Deletes the user! This action is irrecoverable (actually domain admins can do that but probably will shout with you)"""
		try:
			_, err = await self.connection.delete_user(user_dn)
			if err is not None:
				raise err
			print('Goodbye, Caroline.')
		except:
			traceback.print_exc()

	async def do_changeuserpw(self, user_dn, newpass, oldpass = None):
		"""Changes user password, if you are admin then old pw doesnt need to be supplied"""
		try:
			_, err = await self.connection.change_password(user_dn, newpass, oldpass)
			if err is not None:
				raise err
			print('User password changed')
		except:
			traceback.print_exc()

	async def do_unlockuser(self, user_dn):
		"""Unlock user by setting lockoutTime to 0"""
		try:
			_, err = await self.connection.unlock_user(user_dn)
			if err is not None:
				raise err
			print('User unlocked')
		except:
			traceback.print_exc()

	async def do_enableuser(self, user_dn):
		"""Unlock user by flipping useraccountcontrol bits"""
		try:
			_, err = await self.connection.enable_user(user_dn)
			if err is not None:
				raise err
			print('User enabled')
		except:
			traceback.print_exc()

	async def do_disableuser(self, user_dn):
		"""Unlock user by flipping useraccountcontrol bits"""
		try:
			_, err = await self.connection.disable_user(user_dn)
			if err is not None:
				raise err
			print('User disabled')
		except:
			traceback.print_exc()

	async def do_addspn(self, user_dn, spn):
		"""Adds an SPN entry to the users account"""
		try:
			_, err = await self.connection.add_user_spn(user_dn, spn)
			if err is not None:
				raise err
			print('SPN added!')
		except:
			traceback.print_exc()

	async def do_addhostname(self, user_dn, hostname):
		"""Adds additional hostname to computer account"""
		try:
			_, err = await self.connection.add_additional_hostname(user_dn, hostname)
			if err is not None:
				raise err
			print('Hostname added!')
		except:
			traceback.print_exc()
			
	async def do_test(self):
		"""testing, dontuse"""
		try:
			async for entry, err in self.connection.get_all_objectacl():
				if err is not None:
					raise err

				if entry.objectClass[-1] != 'user':
					print(entry.objectClass)
		except:
			traceback.print_exc()

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
	parser.add_argument('commands', nargs='*')

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
