#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import logging
import csv
from msldap.core.msldap import *
from msldap.ldap_objects import *


def run():
	import argparse
	parser = argparse.ArgumentParser(description='MS LDAP library')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('host', help='target IP/hostname (the DC)')
	parser.add_argument('-s', '--use-sspi', action='store_true', help='Use windows built-in authentication. ')
	
	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'
	
	dump_group = subparsers.add_parser('dump', help='Dump all user objects to TSV file')
	dump_group.add_argument('outfile', help='output file')
	
	dump_group.add_argument('username', help='username')
	dump_group.add_argument('-d', help='domain, optional if the username contains the domain as well')
	dump_group.add_argument('-p', help='password, if not supplied you will be prompted in a secure manner')
	dump_group.add_argument('-n', action='store_true', help='Perform NTLM authentication')
	dump_group.add_argument('-t', '--tree', help='tree to perform the queries on')

	spn_group = subparsers.add_parser('spn', help='Dump all user objects to TSV file')
	spn_group.add_argument('outfile', help='output file')
	spn_group.add_argument('username', help='username')
	spn_group.add_argument('-d', help='domain, optional if the username contains the domain as well')
	spn_group.add_argument('-p', help='password, if not supplied you will be prompted in a secure manner')
	spn_group.add_argument('-n', action='store_true', help='Perform NTLM authentication')
	spn_group.add_argument('-t', '--tree', help='tree to perform the queries on')

	dsa_group = subparsers.add_parser('dsa', help='Grab basic info about the AD')

	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	else:
		logging.basicConfig(level=logging.DEBUG)


	if args.command == 'dsa':
		target = MSLDAPTargetServer(args.host)
		ldap = MSLDAP(None, target, args.use_sspi)
		print(ldap.get_server_info())

	elif args.command == 'dump':
		target = MSLDAPTargetServer(args.host, tree = args.tree)
		if args.use_sspi == False:
			creds = MSLDAPUserCredential(username = args.username, domain = args.d, password = args.p, is_ntlm=args.n)
		else:
			creds = None
		ldap = MSLDAP(creds, target, use_sspi = args.use_sspi)
		ldap.connect()
		adinfo = ldap.get_ad_info()
		with open(args.outfile, 'w', newline='', encoding = 'utf8') as f:
			writer = csv.writer(f, delimiter = '\t')
			writer.writerow(MSADUser.TSV_ATTRS)
			for user in ldap.get_all_user_objects():
				writer.writerow(user.get_row(MSADUser.TSV_ATTRS))
				
		with open(args.outfile + '_comp', 'w', newline='', encoding = 'utf8') as f:
			writer = csv.writer(f, delimiter = '\t')
			writer.writerow(MSADMachine.TSV_ATTRS)
			for comp in ldap.get_all_machine_objects():
				writer.writerow(comp.get_row(MSADMachine.TSV_ATTRS))

	elif args.command == 'spn':
		target = MSLDAPTargetServer(args.host, tree = args.tree)
		if args.use_sspi == False:
			creds = MSLDAPUserCredential(username = args.username, domain = args.d, password = args.p, is_ntlm=args.n)
		else:
			creds = None
		ldap = MSLDAP(creds, target, args.use_sspi)
		ldap.connect()
		adinfo = ldap.get_ad_info()
		with open(args.outfile, 'w', newline='', encoding = 'utf8') as f:
			for user in ldap.get_all_service_user_objects():
				f.write(user.sAMAccountName + '\r\n')

if __name__ == '__main__':
	run()
