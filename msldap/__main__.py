import logging
import csv
import os
import sys

from .core.msldap import *
from .core.dbmodel import Basemodel, Project, Credential, get_session, create_db

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

def get_connection_string(args):
	if args.sql is not None and args.sql != '':
		return args.sql
	if 'MSLDAPDB' in os.environ:
		return os.environ['MSLDAPDB']
	else:
		raise Exception('DB connection string missing! Provide if either via the "--sql" parameter or by setting the "MSLDAPDB" environment variable')

def run():
	import argparse
	parser = argparse.ArgumentParser(description='MS LDAP library')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--sql', help='sql engine address, if not present the script will look for the "MSLDAPDB" environment variable')
	
	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'

	db_group = subparsers.add_parser('db', help='Database operations')
	db_group.add_argument('cmd', nargs='?', choices=['create', 'list', 'dump'], default='list', help='Database commands.')
	db_group.add_argument('rest', nargs=argparse.REMAINDER)

	dump_group = subparsers.add_parser('dump', help='Dump all user objects to Database')
	dump_group.add_argument('host', help='target IP/hostname (the DC)')
	dump_group.add_argument('username', help='username')
	dump_group.add_argument('-d', help='domain, optional if the username contains the domain as well')
	dump_group.add_argument('-p', help='password, if not supplied you will be prompted in a secure manner')
	dump_group.add_argument('-n', action='store_true', help='Perform NTLM authentication')
	dump_group.add_argument('-t', '--tree', help='tree to perform the queries on')

	spn_group = subparsers.add_parser('spn', help='Dump all user objects to TSV file')
	spn_group.add_argument('host', help='target IP/hostname (the DC)')
	spn_group.add_argument('outfile', help='output file')
	spn_group.add_argument('username', help='username')
	spn_group.add_argument('-d', help='domain, optional if the username contains the domain as well')
	spn_group.add_argument('-p', help='password, if not supplied you will be prompted in a secure manner')
	spn_group.add_argument('-n', action='store_true', help='Perform NTLM authentication')
	spn_group.add_argument('-t', '--tree', help='tree to perform the queries on')

	dsa_group = subparsers.add_parser('dsa', help='Grab basic info about the AD')
	dsa_group.add_argument('host', help='target IP/hostname (the DC)')

	pot_group = subparsers.add_parser('pot', help='Upload hashcat potfile')
	pot_group.add_argument('potfile', help='output file')
	pot_group.add_argument('--hash-type', default = 'NT', help='hash type to upload. can be NT or LM')

	imp_group = subparsers.add_parser('imp', help='Upload impacket dumps')
	imp_group.add_argument('potfile', help='output file')
	imp_group.add_argument('adid', help='AD table id that defines the scope')
	

	uncracked_group = subparsers.add_parser('uncracked', help='Get a list of hashes with unknown plaintext for projectID')
	uncracked_group.add_argument('adid', help='AD table id that defines the scope')
	uncracked_group.add_argument('--hash-type', default = 'NT', help='hash type to upload. can be NT or LM')
	uncracked_group.add_argument('--history', type=bool, default = False, help='take password history into account')
	uncracked_group.add_argument('-o','--outfile', help='output file to write hashes to, otherwise they will be on stdout')


	cracked_group = subparsers.add_parser('cracked', help='Get a list of users whose password was cracked')
	cracked_group.add_argument('adid', help='AD table id that defines the scope')
	cracked_group.add_argument('--hash-type', default = 'NT', help='hash type to upload. can be NT or LM')
	cracked_group.add_argument('--history', type=bool, default = False, help='take password history into account')
	cracked_group.add_argument('-o','--outfile', help='output file to write hashes to, otherwise they will be on stdout')

	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
		logger.setLevel(logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
		logger.setLevel(logging.DEBUG)
	else:
		logging.basicConfig(level=1)
		logger.setLevel(1)


	if args.command == 'dsa':
		target = MSLDAPTargetServer(args.host)
		ldap = MSLDAP(None, target)
		print(ldap.get_server_info())

	elif args.command == 'db':
		if args.cmd == 'list':
			conn = get_connection_string(args)
			session = get_session(conn, args.verbose)
			logging.debug('Fetching data from DB')
			
			query = session.query(Project)
			for project in query.all():
				print('==== Project ====\nID: %s\nCreated: %s\nName: %s\nCmd: %s\n' % (project.id, project.created_at, project.name, project.cmd))

				for ad in project.ads:
					print('\t== ADinfo ==\n\tID: %s\n\tUser count: %s' % (ad.id,len(ad.users)))

			session.close()

		elif args.cmd == 'create':
			conn = get_connection_string(args)
			create_db(conn, args.verbose)

		else:
			raise Exception('Unsupported DB subcommand %s' % args.cmd)

	elif args.command == 'dump':
		conn = get_connection_string(args)
		session = get_session(conn, args.verbose)
		logging.info('Creating Project entry')
		project = Project('projectname','cmdargs')
		session.add(project)
		session.flush()
		session.refresh(project)
		logging.debug('Got project id: %s' % project.id)
		logging.info('Creating ADInfo entry')
		creds = MSLDAPUserCredential(username = args.username, domain = args.d, password = args.p, is_ntlm=args.n)
		target = MSLDAPTargetServer(args.host, tree = args.tree)
		ldap = MSLDAP(creds, target)
		ldap.connect()
		adinfo = ldap.get_ad_info()
		adinfo.project_id = project.id
		session.add(adinfo)
		session.flush()
		session.refresh(adinfo)
		logging.debug('Got ADInfo id: %s' % adinfo.id)
		logging.info('Inserting users')
		ctr = 0
		for user in ldap.get_all_user_objects():
			ctr += 1
			user.ad_id = adinfo.id #manually updating foreign key
			#logging.log(1, str(user)) #enable this to see user info while dumping, slows down script!
			
			session.add(user)
			if ctr % 1000 == 0:
				session.commit()
		session.commit()
		session.close()
		logging.info('Succsessfully loaded %d users in database!' % ctr)

	elif args.command == 'spn':
		#this is not a DB command!
		creds = MSLDAPUserCredential(username = args.username, domain = args.d, password = args.p, is_ntlm=args.n)
		target = MSLDAPTargetServer(args.host, tree = args.tree)
		ldap = MSLDAP(creds, target)
		ldap.connect()
		adinfo = ldap.get_ad_info()
		with open(args.outfile, 'w', newline='') as f:
			for user in ldap.get_all_service_user_objects():
				f.write(user.sAMAccountName + '\r\n')

	elif args.command == 'imp':
		logging.info('Opening impacket dumpfile')
		with open(args.potfile,'r') as f:
			data = f.readlines()

		logging.info('Parsing dumpfile')
		creds = Credential.from_impacket(data)
		logging.info('Uploading %d credentials to DB!' % len(creds))
		conn = get_connection_string(args)
		session = get_session(conn, args.verbose)
		history_user_filter = {}
		ctr = 0
		for domain, sAMAccountName, cred in creds:
			#filtering historical data where user could not be found
			if sAMAccountName in history_user_filter:
				continue
			#first we need to look up the userid!
			query = session.query(MSADUser).filter(MSADUser.ad_id == args.adid).filter(MSADUser.sAMAccountName == sAMAccountName)
			user = query.first()
			if user is None:
				logging.info('Could not find user %s in DB' % (sAMAccountName,))
				history_user_filter[sAMAccountName] = 0
				continue
			
			#now we add the userid to the credential, and upload it!
			cred.user_id = user.id
			session.add(cred)
			ctr += 1
			if ctr % 1000 == 0:
				session.commit()

		session.commit()
		session.close()
		logging.info('Succsessfully uploaded %d credentials!' % ctr)

	elif args.command == 'pot':
		logging.info('Opening potfile')
		with open(args.potfile,'r') as f:
			data = f.readlines()

		logging.info('Parsing potfile')
		hes = HashEntry.from_potfile(data)
		logging.info('Uploading %s hash-plaintext pairs to DB!' % len(hes))
		conn = get_connection_string(args)
		session = get_session(conn, args.verbose)
		ctr = 0
		for he in hes:
			session.add(he)
			ctr += 1
			if ctr % 1000 == 0:
				session.commit()

		session.commit()
		session.close()
		logging.info('Succsessfully uploaded %d hash-plaintext pairs to DB!' % ctr)


	elif args.command == 'uncracked':
		conn = get_connection_string(args)
		session = get_session(conn, args.verbose)
		
		if args.hash_type == 'NT':
			query = session.query(Credential.nt_hash).filter(MSADUser.ad_id == args.adid).filter(MSADUser.id == Credential.user_id).filter(Credential.nt_hash != None).filter(Credential.nt_hash.notin_(session.query(HashEntry.nt_hash))).distinct(Credential.nt_hash)
		elif args.hash_type == 'LM':
			query = session.query(Credential.lm_hash).filter(MSADUser.ad_id == args.adid).filter(MSADUser.id == Credential.user_id).filter(Credential.lm_hash != None).filter(Credential.lm_hash.notin_(session.query(HashEntry.lm_hash))).distinct(Credential.lm_hash)
		else:
			raise Exception('Unsupported hash type')

		if not args.history:
			query = query.filter(Credential.history_no == None)
		
		if args.outfile:
			with open(args.outfile, 'wb') as f:
				for credential in query.all():
					f.write(str(credential[0])+'\r\n')

		else:
			for credential in query.all():
				print(str(credential[0]))



	elif args.command == 'cracked':
		conn = get_connection_string(args)
		session = get_session(conn, args.verbose)

		if args.hash_type == 'NT':
			query = session.query(MSADUser).filter(MSADUser.ad_id == args.adid).filter(MSADUser.id == Credential.user_id).filter(Credential.nt_hash != None).filter(Credential.nt_hash.in_(session.query(HashEntry.nt_hash)))
		elif args.hash_type == 'LM':
			query = session.query(MSADUser).filter(MSADUser.ad_id == args.adid).filter(MSADUser.id == Credential.user_id).filter(Credential.lm_hash != None).filter(Credential.lm_hash.in_(session.query(HashEntry.lm_hash)))
		else:
			raise Exception('Unsupported hash type')

		if not args.history:
			query = query.filter(Credential.history_no == None)
		
		if args.outfile:
			writer = csv.writer(f, delimiter = '\t')
			writer.writerow(MSADUser.TSV_ATTRS)
			for user in query.all():
				writer.writerow(user.get_row(MSADUser.TSV_ATTRS))

		else:
			print('\t'.join(MSADUser.TSV_ATTRS))
			for user in query.all():

				print('\t'.join([str(x) for x in user.get_row(MSADUser.TSV_ATTRS)]))


if __name__ == '__main__':
	run()
