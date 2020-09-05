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


class MSLDAPCompDomainList:
	def __init__(self, ldap_url):
		self.conn_url = ldap_url
		self.connection = None
		self.adinfo = None
		self.ldapinfo = None
		self.domain_name = None

	async def login(self):
		"""Performs connection and login"""
		try:
			logger.debug(self.conn_url.get_credential())
			logger.debug(self.conn_url.get_target())
			
			
			self.connection = self.conn_url.get_client()
			_, err = await self.connection.connect()
			if err is not None:
				raise err
			
			return True, None
		except Exception as e:
			return False, e

	async def do_adinfo(self, show = True):
		"""Prints detailed Active Driectory info"""
		try:
			if self.adinfo is None:
				self.adinfo = self.connection._ldapinfo
				self.domain_name = self.adinfo.distinguishedName.replace('DC','').replace('=','').replace(',','.')
			if show is True:
				print(self.adinfo)
			
			return True, None
		except Exception as e:
			return False, e

	async def run(self):
		try:
			_, err = await self.login()
			if err is not None:
				raise err
			_, err = await self.do_adinfo(False)
			if err is not None:
				raise err
			#machine_filename = '%s_computers_%s.txt' % (self.domain_name, datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
		
			async for machine, err in self.connection.get_all_machines(attrs=['sAMAccountName', 'dNSHostName']):
				if err is not None:
					raise err
					
				dns = machine.dNSHostName
				if dns is None:
					dns = '%s.%s' % (machine.sAMAccountName[:-1], self.domain_name)

				print(str(dns))
		except:
			traceback.print_exc()


def main():
	import argparse
	parser = argparse.ArgumentParser(description='MS LDAP library')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
	parser.add_argument('-n', '--no-interactive', action='store_true')
	parser.add_argument('url', help='Connection string in URL format.')

	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	else:
		sockslogger.setLevel(logging.DEBUG)
		logger.setLevel(logging.DEBUG)
		logging.basicConfig(level=logging.DEBUG)

	ldap_url = MSLDAPURLDecoder(args.url)
	compdomlist = MSLDAPCompDomainList(ldap_url)


	asyncio.run(compdomlist.run())

if __name__ == '__main__':
	main()