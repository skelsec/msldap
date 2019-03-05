from msldap.core.msldap import MSLDAPTargetServer, MSLDAPUserCredential, MSLDAP
from msldap.core.recon import LDAPRecon

from msldap.core.ms_asn1 import *
from msldap.core.win_data_types import *
from msldap.core.sid import *

if __name__ == '__main__':
	host = '10.10.10.2'
	target = MSLDAPTargetServer(host)
	#creds = MSLDAPUserCredential(username = args.username, domain = args.d, password = args.p, is_ntlm=args.n)
	recon = LDAPRecon(None, target, True)
	
	
	#recon.get_netdomain()
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
	print('1')
	recon.get_all_tokengroups(None)
	print('2')