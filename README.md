# msldap
LDAP library for MS AD

# Features
 - Comes with a built-in console LDAP client
 - All parameters can be conrolled via a conveinent URL (see below)
 - Supports integrated windows authentication
 - Supports SOCKS5 proxy withot the need of extra proxifyer
 - Minimal footprint
 - A lot of pre-built queries for convenient information polling
 - Easy to integrate to your project
 - Completely missing documentation
 - No testing suite

# Installation
Via GIT  
`python3 setup.py install`  
OR  
`pip install msldap`

# Prerequisites
 - `ldap3` module. It's pure python so you dont have to compile anything.
 - `winsspi` module. For windows only. This supports SSPI based authentication.  
 - `asn1crypto` module. Some LDAP queries incorporate ASN1 strucutres to be sent on top of the ASN1 transport XD
 - `socks5line` module. To support socks5 proxying.
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
	MSLDAP URL Format: <protocol>+<auth>://<username>:<password>@<ip_or_host>:<port>/<tree>/?<param>=<value>
	<protocol> sets the ldap protocol following values supported:
		- ldap
		- ldaps (ldap over SSL) << known to be problematic because of the underlying library (ldap3)
	<auth> can be omitted if plaintext authentication is to be performed, otherwise:
		- ntlm
		- sspi (windows only!)
		- anonymous
		- plain
	<param> can be:
		- timeout : connction timeout in seconds
		- proxytype: currently only socks5 proxy is supported
		- proxyhost: Ip or hostname of the proxy server
		- proxyport: port of the proxy server
		- proxytimeout: timeout ins ecodns for the proxy connection

	Examples:
	ldap://10.10.10.2
	ldaps://test.corp
	ldap+sspi:///test.corp
	ldap+ntlm://TEST\\victim:password@10.10.10.2
	ldap://TEST\\victim:password@10.10.10.2/DC=test,DC=corp/
	ldap://TEST\\victim:password@10.10.10.2/DC=test,DC=corp/?timeout=99&proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080&proxytimeout=44
```

# Kudos
This project is built on top of the [ldap3](https://github.com/cannatag/ldap3) project.
