#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import logging
import csv
from msldap.connection import MSLDAPConnection
from msldap.commons.url import MSLDAPURLDecoder
from msldap.ldap_objects import MSADUser, MSADMachine


def run():
	import argparse
	parser = argparse.ArgumentParser(description='MS LDAP library')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
	parser.add_argument('connection', help='Connection string in URL format.')
	parser.add_argument('--tree', help='LDAP tree to perform the searches on')
	
	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'
	
	dump_group = subparsers.add_parser('dump', help='Dump all user objects to TSV file')
	dump_group.add_argument('outfile', help='output file')

	spn_group = subparsers.add_parser('spn', help='Dump all users with servicePrincipalName attribute set to TSV file')
	spn_group.add_argument('outfile', help='output file')

	dsa_group = subparsers.add_parser('dsa', help='Grab basic info about the AD')

	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	else:
		logging.basicConfig(level=logging.DEBUG)

	url_dec = MSLDAPURLDecoder(args.connection)
	creds = url_dec.get_credential()
	target = url_dec.get_target()
	print(str(creds))
	print(str(target))
	connection = MSLDAPConnection(creds, target)

	if args.command == 'dsa':
		print(connection.get_server_info())

	elif args.command == 'dump':
		connection.connect()
		adinfo = connection.get_ad_info()
		with open(args.outfile, 'w', newline='', encoding = 'utf8') as f:
			writer = csv.writer(f, delimiter = '\t')
			writer.writerow(MSADUser.TSV_ATTRS)
			for user in connection.get_all_user_objects():
				writer.writerow(user.get_row(MSADUser.TSV_ATTRS))
				
		with open(args.outfile + '_comp', 'w', newline='', encoding = 'utf8') as f:
			writer = csv.writer(f, delimiter = '\t')
			writer.writerow(MSADMachine.TSV_ATTRS)
			for comp in connection.get_all_machine_objects():
				writer.writerow(comp.get_row(MSADMachine.TSV_ATTRS))

	elif args.command == 'spn':
		connection.connect()
		adinfo, err = connection.get_ad_info()
		with open(args.outfile, 'w', newline='', encoding = 'utf8') as f:
			for user in connection.get_all_service_user_objects():
				f.write(user.sAMAccountName + '\r\n')

if __name__ == '__main__':
	run()
