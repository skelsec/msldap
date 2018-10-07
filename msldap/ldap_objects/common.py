#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum
from datetime import datetime

def vn(x):
	"""
	value or none, returns none if x is an empty list
	"""
	if x == []:
		return None
	if isinstance(x, list):
		return '|'.join(x)
	if isinstance(x, datetime):
		return x.isoformat()
	return x

class MSLDAP_UAC(enum.IntFlag):
	SCRIPT = 0x00000001  #[ADS_UF_SCRIPT](https://msdn.microsoft.com/library/aa772300) 	The logon script is executed.
	ACCOUNTDISABLE = 0x00000002  #[ADS_UF_ACCOUNTDISABLE](https://msdn.microsoft.com/library/aa772300) 	The user account is disabled.
	HOMEDIR_REQUIRED = 0x00000008  #[ADS_UF_HOMEDIR_REQUIRED](https://msdn.microsoft.com/library/aa772300) 	The home directory is required.
	LOCKOUT = 0x00000010  #[ADS_UF_LOCKOUT](https://msdn.microsoft.com/library/aa772300) 	The account is currently locked out.
	PASSWD_NOTREQD = 0x00000020  #[ADS_UF_PASSWD_NOTREQD](https://msdn.microsoft.com/library/aa772300) 	No password is required.
	PASSWD_CANT_CHANGE = 0x00000040  #[ADS_UF_PASSWD_CANT_CHANGE](https://msdn.microsoft.com/library/aa772300) 	The user cannot change the password.
	ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080  #[ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED](https://msdn.microsoft.com/library/aa772300) 	The user can send an encrypted password.
	TEMP_DUPLICATE_ACCOUNT = 0x00000100  #[ADS_UF_TEMP_DUPLICATE_ACCOUNT](https://msdn.microsoft.com/library/aa772300) 	This is an account for users whose primary account is in another domain. This 	account provides user access to this domain, but not to any domain that trusts this domain. Also known as a local user account.	
	NORMAL_ACCOUNT = 0x00000200  #[ADS_UF_NORMAL_ACCOUNT](https://msdn.microsoft.com/library/aa772300) 	This is a default account type that represe	nts a typical user.	
	INTERDOMAIN_TRUST_ACCOUNT = 0x00000800  #[ADS_UF_INTERDOMAIN_TRUST_ACCOUNT](https://msdn.microsoft.com/library/aa772300) 	This is a permit to trust accou	nt for a system domain that trusts other do	mains.
	WORKSTATION_TRUST_ACCOUNT = 0x00001000  #[ADS_UF_WORKSTATION_TRUST_ACCOUNT](https://msdn.microsoft.com/library/aa772300) 	This is a computer account for 	a computer that is a member of this domain.	
	SERVER_TRUST_ACCOUNT = 0x00002000  #[ADS_UF_SERVER_TRUST_ACCOUNT](https://msdn.microsoft.com/library/aa772300) 	This is a computer account for a system	 backup domain controller that is a member 	of 	this domain.	
	NA_1 = 0x00004000 	#	N/A 	Not used.
	NA_2 = 0x00008000 	#	N/A 	Not used.
	DONT_EXPIRE_PASSWD = 0x00010000 	 #[ADS_UF_DONT_EXPIRE_PASSWD](https://msdn.microsoft.com/library/aa772300) 	The password for this account will never expire.
	MNS_LOGON_ACCOUNT = 0x00020000 	 #[ADS_UF_MNS_LOGON_ACCOUNT](https://msdn.microsoft.com/library/aa772300) 	This is an MNS logon account.
	SMARTCARD_REQUIRED = 0x00040000 	 #[ADS_UF_SMARTCARD_REQUIRED](https://msdn.microsoft.com/library/aa772300) 	The user must log on using a smart card.
	TRUSTED_FOR_DELEGATION = 0x00080000 	 #[ADS_UF_TRUSTED_FOR_DELEGATION](https://msdn.microsoft.com/library/aa772300) 	The service account (user or computer account), under which a service runs, is 	trusted for 	Kerberos delegation. Any such service can impersonate a client requesting the service.	
	NOT_DELEGATED = 0x00100000 	 #[ADS_UF_NOT_DELEGATED](https://msdn.microsoft.com/library/aa772300) 	The security c	ontext of the user will not be delegated to a service even if the service	 	account is s	et as trusted for Kerberos delegation.	
	USE_DES_KEY_ONLY = 0x00200000 	 #[ADS_UF_USE_DES_KEY_ONLY](https://msdn	.microsoft.com/library/aa772300) 	Restrict this principal to use only Data Encryption Standard (DES) encryption types for 	keys.	
	DONT_REQUIRE_PREAUTH = 0x00400000  #[ADS_UF_DONT_REQUIRE_PREAUTH](https://msdn.microsoft.com/library/aa772300) 	This account does not require Kerberos pre-authentication for logon.
	PASSWORD_EXPIRED = 0x00800000  #[ADS_UF_PASSWORD_EXPIRED](https://msdn.microsoft.com/library/aa772300) 	The user password has expired. This flag is created by the system using data from the [	Pwd-L	ast-Set](a-pwdlastset.md) attribute and the domain policy.	
	TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000  #[ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION](https://msdn.microsoft.com/library/aa772300) 	The account is enabled for delegation. This is a security-sensi	tive 	setting; accounts with this option enabled should be strictly controlled. This setting enables a service running under the account to assume a client identity and authenticate 	as that user to other remote servers on the network.