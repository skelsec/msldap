import logging
import csv
from msldap.core.msldap import UserCredential, TargetServer, MSLDAP
from msldap.ldap_objects.aduser import MSADUser

def run():
	import argparse
	parser = argparse.ArgumentParser(description='MS LDAP library')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('host', help='target IP/hostname (the DC)')
	
	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'
	
	dump_group = subparsers.add_parser('dump', help='Dump all user objects to TSV file')
	dump_group.add_argument('outfile', help='output file')
	dump_group.add_argument('tree', help='tree to perform the queries on (HELP: get basic info with dsa command)')

	dump_group.add_argument('username', help='username')
	dump_group.add_argument('-d', help='domain, optional if the username contains the domain as well')
	dump_group.add_argument('-p', help='password, if not supplied you will be prompted in a secure manner')

	dsa_group = subparsers.add_parser('dsa', help='Grab basic info about the AD')

	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	else:
		logging.basicConfig(level=logging.DEBUG)


	if args.command == 'dsa':
		target = TargetServer(None, args.host)
		ldap = MSLDAP(None, target)
		print(ldap.get_server_info())

	elif args.command == 'dump':
		creds = UserCredential(username = args.username, domain = args.d, password = args.p)
		target = TargetServer(args.tree, args.host)
		ldap = MSLDAP(creds, target)
		ldap.connect()
		adinfo = ldap.get_ad_info()
		with open(args.outfile, 'w', newline='') as f:
			writer = csv.writer(f, delimiter = '\t')
			writer.writerow(MSADUser.TSV_ATTRS)
			for user in ldap.get_all_user_objects():
				writer.writerow(user.get_row(MSADUser.TSV_ATTRS))

if __name__ == '__main__':
	run()
