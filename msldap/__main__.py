import logging
import csv
from .core.msldap import *
from .core.dbmodel import Basemodel, Project, Credential

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker


def run():
	import argparse
	parser = argparse.ArgumentParser(description='MS LDAP library')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'
	
	dump_group = subparsers.add_parser('dump', help='Dump all user objects to TSV file')
	dump_group.add_argument('host', help='target IP/hostname (the DC)')
	dump_group.add_argument('outfile', help='output file')
	dump_group.add_argument('username', help='username')
	dump_group.add_argument('-d', help='domain, optional if the username contains the domain as well')
	dump_group.add_argument('-p', help='password, if not supplied you will be prompted in a secure manner')
	dump_group.add_argument('-n', action='store_true', help='Perform NTLM authentication')
	dump_group.add_argument('-t', '--tree', help='tree to perform the queries on')
	dump_group.add_argument('--sql', help='sql engine address')

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
	pot_group.add_argument('--sql', help='sql engine address')
	pot_group.add_argument('potfile', help='output file')
	pot_group.add_argument('--hash-type', default = 'NT', help='hash type to upload. can be NT or LM')

	imp_group = subparsers.add_parser('imp', help='Upload impacket dumps')
	imp_group.add_argument('--sql', help='sql engine address')
	imp_group.add_argument('potfile', help='output file')
	imp_group.add_argument('adid', help='adid')
	

	uncracked_group = subparsers.add_parser('uncracked', help='Get a list of hashes with unknown plaintext for projectID')
	uncracked_group.add_argument('adid', help='adid')
	uncracked_group.add_argument('--hash-type', default = 'NT', help='hash type to upload. can be NT or LM')
	uncracked_group.add_argument('--sql', help='sql engine address')
	uncracked_group.add_argument('--history', type=bool, default = False, help='take password history into account')

	cracked_group = subparsers.add_parser('cracked', help='Get a list of users whose password was cracked')
	cracked_group.add_argument('adid', help='adid')
	cracked_group.add_argument('outfile', help='output file')
	cracked_group.add_argument('--sql', help='sql engine address')
	cracked_group.add_argument('--hash-type', default = 'NT', help='hash type to upload. can be NT or LM')
	cracked_group.add_argument('--history', type=bool, default = False, help='take password history into account')

	list_group = subparsers.add_parser('list', help='List database info')
	list_group.add_argument('--sql', help='sql engine address')

	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	else:
		logging.basicConfig(level=logging.DEBUG)


	if args.command == 'dsa':
		target = MSLDAPTargetServer(args.host)
		ldap = MSLDAP(None, target)
		print(ldap.get_server_info())

	elif args.command == 'list':
		engine = create_engine(args.sql) #'sqlite:///dump.db'
		Session = sessionmaker(bind=engine)
		session = Session()
		print('Fetching data from DB')
		
		query = session.query(Project)
		for project in query.all():
			print('==== Project ====\nID: %s\nCreated: %s\nName: %s\nCmd: %s\n' % (project.id, project.created_at, project.name, project.cmd))

			for ad in project.ads:
				print('\t== ADinfo ==\n\tID: %s\n\tUser count: %s' % (ad.id,len(ad.users)))

		session.close()


	elif args.command == 'dump':
		
		if args.sql is not None:
			print('Creating database %s' % args.sql)
			engine = create_engine(args.sql, echo=True) #'sqlite:///dump.db'	
			Basemodel.metadata.create_all(engine)
			print('Done creating database %s' % args.sql)
			print('Creating session')
			# create a configured "Session" class
			Session = sessionmaker(bind=engine)

			# create a Session
			session = Session()
			print('Creating Project entry')
			project = Project('projectname','cmdargs')
			session.add(project)
			session.flush()
			session.refresh(project)
			print('Got project id: %s' % project.id)

			print('Creating ADInfo entry')

			creds = MSLDAPUserCredential(username = args.username, domain = args.d, password = args.p, is_ntlm=args.n)
			target = MSLDAPTargetServer(args.host, tree = args.tree)
			ldap = MSLDAP(creds, target)
			ldap.connect()
			adinfo = ldap.get_ad_info()
			adinfo.project_id = project.id
			input(str(adinfo))
			session.add(adinfo)
			session.flush()
			session.refresh(adinfo)
			print('Got ADInfo id: %s' % adinfo.id)

			print('Inserting users')
			for user in ldap.get_all_user_objects():
				user.ad_id = adinfo.id
				print(str(user))
				session.add(user)
				session.commit()

			session.commit()
			session.close()

			print('Done!')



		else:
			creds = MSLDAPUserCredential(username = args.username, domain = args.d, password = args.p, is_ntlm=args.n)
			target = MSLDAPTargetServer(args.host, tree = args.tree)
			ldap = MSLDAP(creds, target)
			ldap.connect()
			adinfo = ldap.get_ad_info()
			with open(args.outfile, 'w', newline='') as f:
				writer = csv.writer(f, delimiter = '\t')
				writer.writerow(MSADUser.TSV_ATTRS)
				for user in ldap.get_all_user_objects():
					writer.writerow(user.get_row(MSADUser.TSV_ATTRS))

	elif args.command == 'spn':
		creds = MSLDAPUserCredential(username = args.username, domain = args.d, password = args.p, is_ntlm=args.n)
		target = MSLDAPTargetServer(args.host, tree = args.tree)
		ldap = MSLDAP(creds, target)
		ldap.connect()
		adinfo = ldap.get_ad_info()
		with open(args.outfile, 'w', newline='') as f:
			for user in ldap.get_all_service_user_objects():
				f.write(user.sAMAccountName + '\r\n')

	elif args.command == 'imp':
		print('Opening impacket dumpfile')
		with open(args.potfile,'r') as f:
			data = f.readlines()

		print('Parsing dumpfile')
		creds = Credential.from_impacket(data)
		print('Uploading parsed data!')
		engine = create_engine(args.sql, echo=True)
		Session = sessionmaker(bind=engine)
		session = Session()
		for domain, sAMAccountName, cred in creds:
			#first we need to look up the userid!
			query = session.query(MSADUser).filter(MSADUser.ad_id == args.adid).filter(MSADUser.sAMAccountName == sAMAccountName)
			user = query.first()
			if user is None:
				print('Could not find user %s in DB' % (sAMAccountName,))
				continue
			#now we add the userid to the credential, and upload it!
			cred.user_id = user.id
			session.add(cred)

		session.commit()
		session.close()
		print('Done!')

	elif args.command == 'pot':
		print('Opening potfile')
		with open(args.potfile,'r') as f:
			data = f.readlines()

		print('Parsing potfile')
		hes = HashEntry.from_potfile(data)
		print('Uploading parsed data!')
		engine = create_engine(args.sql, echo=True)
		Session = sessionmaker(bind=engine)
		session = Session()
		for he in hes:
			session.add(he)
		session.commit()
		session.close()
		print('Done!')


	elif args.command == 'uncracked':
		engine = create_engine(args.sql, echo=True)
		Session = sessionmaker(bind=engine)
		session = Session()

		
		if args.hash_type == 'NT':
			query = session.query(Credential.nt_hash).filter(MSADUser.ad_id == args.adid).filter(MSADUser.id == Credential.user_id).filter(Credential.nt_hash != None).filter(Credential.nt_hash.notin_(session.query(HashEntry.nt_hash))).distinct(Credential.nt_hash)
		elif args.hash_type == 'LM':
			query = session.query(Credential.lm_hash).filter(MSADUser.ad_id == args.adid).filter(MSADUser.id == Credential.user_id).filter(Credential.lm_hash != None).filter(Credential.lm_hash.notin_(session.query(HashEntry.lm_hash))).distinct(Credential.lm_hash)
		else:
			print('Unsupported hash type')
			sys.exit()

		if not args.history:
			query = query.filter(Credential.history_no == None)
		
		for credential in query.all():
			print(str(credential[0]))



	elif args.command == 'cracked':
		engine = create_engine(args.sql, echo=True)
		Session = sessionmaker(bind=engine)
		session = Session()

		if args.hash_type == 'NT':
			query = session.query(MSADUser).filter(MSADUser.ad_id == args.adid).filter(MSADUser.id == Credential.user_id).filter(Credential.nt_hash != None).filter(Credential.nt_hash.in_(session.query(HashEntry.nt_hash)))
		elif args.hash_type == 'LM':
			query = session.query(MSADUser).filter(MSADUser.ad_id == args.adid).filter(MSADUser.id == Credential.user_id).filter(Credential.lm_hash != None).filter(Credential.lm_hash.in_(session.query(HashEntry.lm_hash)))
		else:
			print('Unsupported hash type')
			sys.exit()

		if not args.history:
			query = query.filter(Credential.history_no == None)
		
		for user in query.all():
			input(str(user))


if __name__ == '__main__':
	run()
