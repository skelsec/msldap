from uniauth.common.credentials.spnego import SPNEGOCredential
from uniauth.common.constants import  UniAuthProtocol
from uniauth.common.credentials import UniCredential

def get_auth_context(credential:UniCredential):
	if credential.protocol in [UniAuthProtocol.NTLM, UniAuthProtocol.KERBEROS]:
		spnego = SPNEGOCredential([credential])
		return spnego.build_context()
		
	elif credential.protocol == UniAuthProtocol.SICILY:
		return credential.build_context()

	elif credential.protocol in [UniAuthProtocol.SIMPLE, UniAuthProtocol.PLAIN]:
		return credential

	else:
		raise Exception('Unsupported authentication protocol "%s"' % credential.protocol)
		