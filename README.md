# msldap
LDAP library for MS AD

# Installation
`python3 setup.py install`

# Prerequirements
Only the `ldap3` module. It's pure python so you dont have to compile anything.

# Usage
Currenty two commands available.
## dsa
This command will fetch the DSA info after performing an anonymous BIND to the AD.
### Example
`msldap 10.0.0.1 dsa`  
`msldap <AD_IP> dsa`

## dump
Fetches all user objects from the AD and creates a neat TSV file.  
Authentication is a must, also you'll need to supply the domain tree (see example).

### Example
Following cmd will create a TSV file (can be opened by Excel) called `test.tsv`.  
You may supply the password in command line with the `-p` option OR you will be prompted for it.   
Info: you don't need to be a user with elevated privs, any generic user account will work.

`msldap 10.0.0.1 dump test.tsv DC=TEST,DC=corp TEST\user`  
`msldap <AD_IP> dump <outputfile> <tree> <username_with_domain>`
