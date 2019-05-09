# msldap
LDAP library for MS AD

# Important
Version 0.1.0 checnes some API calls and object names, so you'll need to update them in your code.  
It is not likely that changes to the already existing API/object names will be made in the future, but this was needed.  
Sorry for inconveinence.

# LDAP connection string
The major change was needed in version 0.1.0 to unify different connection options as one single string, without the need for additional command line switches.  
The new connection string is composed in the following manner:  
`<domain>/<user>/<secret_type>:<secret>@<target_ip_or_hostname>`  
Detailed explanation with examples:  
```
ldap_connection_string secret types: 
   - Plaintext: "pw" or "pass" or "password"
   - NT hash: "nt"
   - SSPI: "sspi" 
   
   Example:
   - Plaintext:
      TEST/user/pw:@192.168.1.1 (you will be propted for password)
      TEST/user/pw:SecretPassword@192.168.1.1
      TEST/user/password:SecretPassword@192.168.1.1
      TEST/user/pass:SecretPassword@192.168.1.1
   - NT hash:
      TEST/user/nt:921a7fece11f4d8c72432e41e40d0372@192.168.1.1
   - SSPI:
      TEST/user/sspi:@192.168.1.1
```

# Installation
`python3 setup.py install`  
OR  
`pip msldap install`

# Prerequisites
 - `ldap3` module. It's pure python so you dont have to compile anything.
 - `winsspi` module. For windows only. This supports SSPI based authentication.  
 
# Usage
Please not that this is a library, and was not intended to be used as a command line program.  
Despite the statement above, when installing this module it will create an executable called `msldap` that can be used via the command line.  
Currenty two commands available, `dsa` and `dump`
## dsa
This command will fetch the DSA info after performing an anonymous BIND to the AD.  
### Example 
`msldap TEST/victim/anonymous:@10.10.10.2 dump a.tsv`  
Please note that domain and username in teh connection string is irrelevant, only the `anonymous` secret type and the target server is important.

## dump
Fetches all user objects from the AD and creates a neat TSV file.  
Authentication is a must, also you'll need to supply the domain tree (see example).

### Example
Following cmd will create a TSV file (can be opened by Excel) called `test.tsv`.  
Protip: you don't need to be a user with elevated privs, any generic user account will work.

`msldap TEST/victim/pass:@10.10.10.2 dump test.tsv`  
