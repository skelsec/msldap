![Supported Python versions](https://img.shields.io/badge/python-3.6+-blue.svg) [![Documentation Status](https://readthedocs.org/projects/msldap/badge/?version=latest)](https://msldap.readthedocs.io/en/latest/?badge=latest) [![Twitter](https://img.shields.io/twitter/follow/skelsec?label=skelsec&style=social)](https://twitter.com/intent/follow?screen_name=skelsec)

:triangular_flag_on_post: This is the public repository of msldap, for latest version and updates please consider supporting us through https://porchetta.industries/

# msldap
LDAP library for MS AD
![Documentation Status](https://user-images.githubusercontent.com/19204702/81515211-3761e880-9333-11ea-837f-bcbe2a67ee48.gif )

## :triangular_flag_on_post: Sponsors

If you want to sponsors this project and have the latest updates on this project, latest issues fixed, latest features, please support us on https://porchetta.industries/

## Official Discord Channel

Come hang out on Discord!

[![Porchetta Industries](https://discordapp.com/api/guilds/736724457258745996/widget.png?style=banner3)](https://discord.gg/ycGXUxy)


# Documentation
[Awesome documentation here!](https://msldap.readthedocs.io/en/latest/)

# Features
 - Comes with a built-in console LDAP client
 - All parameters can be conrolled via a conveinent URL (see below)
 - Supports integrated windows authentication (SSPI) both with NTLM and with KERBEROS
 - Supports channel binding (for ntlm and kerberos not SSPI)
 - Supports encryption (for NTLM/KERBEROS/SSPI)
 - Supports LDAPS (TODO: actually verify certificate)
 - Supports SOCKS5 proxy withot the need of extra proxifyer
 - Minimal footprint
 - A lot of pre-built queries for convenient information polling
 - Easy to integrate to your project
 - No testing suite

# Installation
Via GIT  
`python3 setup.py install`  
OR  
`pip install msldap`

# Prerequisites
 - `asn1crypto` module. Some LDAP queries incorporate ASN1 strucutres to be sent on top of the ASN1 transport XD
 - `asysocks` module. To support socks proxying.
 - `aiocmd` For the interactive client
 - `asciitree` For plotting nice trees in the interactive client
 
# Usage
Please note that this is a library, and was not intended to be used as a command line program.  
Whit this noted, the projects packs a fully functional LDAP interactive client. When installing the `msldap` module with `setup.py install` a new binary will appear called `msldap` (shocking naming conventions)  

# LDAP connection URL
The major change was needed in version 0.2.0 to unify different connection options as one single string, without the need for additional command line switches.  
The new connection string is composed in the following manner:  
`<protocol>+<auth_method>://<domain>\<username>:<password>@<ip>:<port>/?<param>=<value>&<param>=<value>&...`  
Detailed explanation with examples:  
```	
<protocol>+<auth>://<username>:<password>@<ip_or_host>:<port>/<tree>/?<param>=<value>


	<protocol> sets the ldap protocol following values supported:
		- ldap
		- ldaps
		
	<auth> can be omitted if plaintext authentication is to be performed (in that case it default to ntlm-password), otherwise:
		- ntlm-password
		- ntlm-nt
		- kerberos-password (dc option param must be used)
		- kerberos-rc4 / kerberos-nt (dc option param must be used)
		- kerberos-aes (dc option param must be used)
		- kerberos-keytab (dc option param must be used)
		- kerberos-ccache (dc option param must be used)
		- kerberos-pfx (dc option param must be used)
		- kerberos-pem (dc option param must be used)
		- kerberos-certstore (dc option param must be used, windows only)
		- sspi-ntlm (windows only!)
		- sspi-kerberos (windows only!)
		- anonymous
		- plain
		- simple
		- sicily (same format as ntlm-nt but using the SICILY authentication)
		
	<tree>:
		OPTIONAL. Specifies the root tree of all queries
		
	<param> can be:
		- timeout : connction timeout in seconds
		- proxytype: currently only socks5 proxy is supported
		- proxyhost: Ip or hostname of the proxy server
		- proxyport: port of the proxy server
		- proxytimeout: timeout ins ecodns for the proxy connection
		- dc: the IP address of the domain controller, MUST be used for kerberos authentication

	Examples:
	ldap://10.10.10.2 (anonymous bind)
	ldaps://test.corp (anonymous bind)
	ldap+sspi-ntlm://test.corp
	ldap+sspi-kerberos://test.corp
	ldap://TEST\\victim:<password>@10.10.10.2 (defaults to SASL GSSAPI NTLM)
	ldap+simple://TEST\\victim:<password>@10.10.10.2 (SASL SIMPLE auth)
	ldap+plain://TEST\\victim:<password>@10.10.10.2 (SASL SIMPLE auth)
	ldap+ntlm-password://TEST\\victim:<password>@10.10.10.2
	ldap+ntlm-nt://TEST\\victim:<nthash>@10.10.10.2
	ldap+kerberos-password://TEST\\victim:<password>@10.10.10.2
	ldap+kerberos-rc4://TEST\\victim:<rc4key>@10.10.10.2
	ldap+kerberos-aes://TEST\\victim:<aes>@10.10.10.2
	ldap://TEST\\victim:password@10.10.10.2/DC=test,DC=corp/
	ldap://TEST\\victim:password@10.10.10.2/DC=test,DC=corp/?timeout=99&proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080&proxytimeout=44
```

# Kudos
Certificate services functionality was based on [certi](https://github.com/zer1t0/certi) created by @zer1t0
