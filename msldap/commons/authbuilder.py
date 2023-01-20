from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.constants import  asyauthProtocol
from asyauth.common.credentials import UniCredential

def get_auth_context(credential:UniCredential):
	if credential.protocol in [asyauthProtocol.NTLM, asyauthProtocol.KERBEROS]:
		spnego = SPNEGOCredential([credential])
		return spnego.build_context()
		
	elif credential.protocol == asyauthProtocol.SICILY:
		return credential.build_context()

	elif credential.protocol in [asyauthProtocol.SIMPLE, asyauthProtocol.PLAIN, asyauthProtocol.NONE, asyauthProtocol.SSL]:
		return credential

	else:
		raise Exception('Unsupported authentication protocol "%s"' % credential.protocol)
		