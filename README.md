# msldap
LDAP library for MS AD

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
<protocol>: "ldap" or "ldaps"
<auth_method> (opt): "ntlm" or "sspi" default is ntlm

<param> (opt): <proxtype> <proxyauth> <proxyhost> <proxyport> <proxyuser> <proxpass>

Examples:
   ldap://10.10.10.2
   ldap://TEST\\victim:password@10.10.10.2
   ldap+ntlm://TEST\\victim:password@10.10.10.2
   ldap+ntlm://TEST\\victim:<NT_hash>@10.10.10.2
   ldap+sspi://10.10.10.2
   ldap://TEST\\victim:password@10.10.10.2/?proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080

IMPORTANT! Based on your shell, the backslash operator (separating the user and domain) can be destorying the url. Be careful
```
