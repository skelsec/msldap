#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import asyncio
import traceback
import logging
import csv

from aiocmd import aiocmd
from asciitree import LeftAligned
import ldap3

from msldap.connection import MSLDAPConnection
from msldap.commons.url import MSLDAPURLDecoder
from msldap.ldap_objects import MSADUser, MSADMachine


class MSLDAPClient(aiocmd.PromptToolkitCmd):
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
			print('url %s' % repr(url))
			
			if self.conn_url is None and url is None:
				print('Not url was set, cant do logon')
			if url is not None:
				self.conn_url = MSLDAPURLDecoder(url)

			print(self.conn_url.get_credential())
			print(self.conn_url.get_target())
			
			
			self.connection = self.conn_url.get_connection()
			self.connection.connect()
			print(self.connection._tree)
			
		except Exception as e:
			traceback.print_exc()

	async def do_ldapinfo(self, show = True):
		"""Prints detailed LDAP connection info (DSA)"""
		try:
			if self.ldapinfo is None:
				self.ldapinfo = self.connection.get_server_info()
			if show is True:
				print(self.ldapinfo)
		except Exception as e:
			traceback.print_exc()

	async def do_adinfo(self, show = True):
		"""Prints detailed Active Driectory info"""
		try:
			if self.adinfo is None:
				self.adinfo = self.connection.get_ad_info()
			if show is True:
				print(self.adinfo)
		except Exception as e:
			traceback.print_exc()

	async def do_spns(self):
		"""Fetches kerberoastable user accounts"""
		try:
			await self.do_ldapinfo(False)
			for user in self.connection.get_all_service_user_objects():
				print(user.sAMAccountName)
		except Exception as e:
			traceback.print_exc()
	
	async def do_asrep(self):
		"""Fetches ASREP-roastable user accounts"""
		try:
			await self.do_ldapinfo(False)
			for user in self.connection.get_all_knoreq_user_objects():
				print(user.sAMAccountName)
		except Exception as e:
			traceback.print_exc()


	async def do_dump(self):
		"""Fetches ALL user and machine accounts from the domain with a LOT of attributes"""
		try:
			await self.do_adinfo(False)
			await self.do_ldapinfo(False)
			for user in self.connection.get_all_user_objects():
				print(user.get_row(MSADUser.TSV_ATTRS))
			#with open(args.outfile, 'w', newline='', encoding = 'utf8') as f:
			#	writer = csv.writer(f, delimiter = '\t')
			#	writer.writerow(MSADUser.TSV_ATTRS)
			#	for user in connection.get_all_user_objects():
			#		writer.writerow(user.get_row(MSADUser.TSV_ATTRS))
		except Exception as e:
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
			for entry in self.connection.pagedsearch(query, attributes):
				print(entry)
		except Exception as e:
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
			tree_data = self.connection.get_tree_plot(dn, level)
			tr = LeftAligned()
			print(tr(tree_data))


		except Exception as e:
			traceback.print_exc()

	async def do_user(self, samaccountname):
		"""Feteches a user object based on the sAMAccountName of the user"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			for user in self.connection.get_user(samaccountname):
				print(user)
		except Exception as e:
			traceback.print_exc()

	async def do_acl(self, dn):
		"""Feteches security info for a given DN"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			for sec_info in self.connection.get_objectacl_by_dn(dn):
				print(sec_info)
		except Exception as e:
			traceback.print_exc()

	async def do_gpos(self):
		"""Feteches security info for a given DN"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			for gpo in self.connection.get_all_gpos():
				print(gpo)
		except Exception as e:
			traceback.print_exc()

	async def do_laps(self):
		"""Feteches all laps passwords"""
		try:
			for entry in self.connection.get_all_laps():
				print(entry)
		except ldap3.core.exceptions.LDAPAttributeError:
			print('Attribute error! LAPS is probably not used. If it is used, and you see this error please submit an issue on GitHub')
		except Exception as e:
			traceback.print_exc()

	async def do_groupmembership(self, dn):
		"""Feteches names all groupnames the user is a member of for a given DN"""
		try:
			await self.do_ldapinfo(False)
			await self.do_adinfo(False)
			group_sids = []
			for group_sid in self.connection.get_tokengroups(dn):
				group_sids.append(group_sids)
				group_dn = self.connection.get_dn_for_objectsid(group_sid)
				print('%s - %s' % (group_dn, group_sid))
				
			if len(group_sids) == 0:
				print('No memberships found')
		except Exception as e:
			traceback.print_exc()

	async def do_bindtree(self, newtree):
		"""Changes the LDAP TREE for future queries. 
				 MUST be DN format eg. 'DC=test,DC=corp'
				 !DANGER! Switching tree to a tree outside of the domain will trigger a connection to that domain, leaking credentials!"""
		self.connection._tree = newtree
	
	"""
	async def do_info(self):
		try:

		except Exception as e:
			traceback.print_exc()
	"""

def main():
	import argparse
	parser = argparse.ArgumentParser(description='MS LDAP library')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
	parser.add_argument('url', help='Connection string in URL format.')

	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	else:
		logging.basicConfig(level=logging.DEBUG)

	asyncio.get_event_loop().run_until_complete(MSLDAPClient(args.url).run())

if __name__ == '__main__':
	main()
