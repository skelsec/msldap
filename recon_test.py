from msldap.core.msldap import MSLDAPTargetServer, MSLDAPUserCredential, MSLDAP
#from msldap.core.recon import LDAPRecon

from msldap.core.ms_asn1 import *
from msldap.core.win_data_types import *
from msldap.core.sid import *

if __name__ == '__main__':
	host = '10.10.10.2'
	target = MSLDAPTargetServer(host)
	#creds = MSLDAPUserCredential(username = args.username, domain = args.d, password = args.p, is_ntlm=args.n)
	recon = MSLDAP(None, target, use_sspi = True)
	recon.connect()
	
	
	#recon.get_netdomain()
	#recon.get_domaincontroller()
	#recon.get_all_groups()
	#recon.get_group_by_dn('CN=Administrators,CN=Builtin,DC=test,DC=corp')
	#for user in recon.get_group_members('CN=Administrators,CN=Builtin,DC=test,DC=corp', False):
	#	print(str(user))
	recon.get_permissions_for_dn('CN=victim,CN=Users,DC=test,DC=corp')

	#recon.get_netcomputer()
	#print('==== Printer ====')
	#recon.get_netprinter()
	#print('==== ACLs ====')
	#recon.get_objectacl()
	#print('==== SID test ====')
	#sid = SID.from_string('S-1-5-21-3448413973-1765323015-1500960949-1109')
	#recon.get_adobject(sid)
	#for sid in recon.get_tokengroups('CN=victim,CN=Users,DC=test,DC=corp'):
	#	recon.get_adobject(sid)
	#recon.test()
	#recon.get_all_objectacl().
	#print('1')
	#recon.get_all_tokengroups(None)
	#print('2')