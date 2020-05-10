URL based examples
###################
| Both the connection and the authentication can be controlled via the `url` parameter.
| The same example code will be used in this tutorial, only the `url` parameter will change

Sample code
""""""""""""
.. literalinclude:: ../../examples/client.py
   :emphasize-lines: 4

Authentication
"""""""""""""""

Simple bind
---------------
| username and password

.. code:: python

	'ldap+simple://TEST\\victim:Passw0rd!1@10.10.10.2'

Sicily bind
---------------
| The sicily bind was created by Microsoft and provides the same mechanisms as "GSSAPI - NTLM"

| username and password

.. code:: python

	'ldap+sicily://TEST\\victim:Passw0rd!1@10.10.10.2'


GSSAPI - NTLM bind
--------------------
| username and password

.. code:: python

	'ldap+ntlm-password://TEST\\victim:Passw0rd!1@10.10.10.2'

| NT hash of the user

.. code:: python

	'ldap+ntlm-nt://TEST\\victim:f8963568a1ec62a3161d9d6449baba93@10.10.10.2'

| SSPI integrated auth. This will use the current user's authentication context. The username doesn't matter, but the correct domain must be set! Windows only 

.. code:: python

	'ldap+sspi-ntlm://TEST\\victim@10.10.10.2'

GSSAPI - Kerberos bind
------------------------
.. warning:: For kerberos authentication type, the `dc` parameter with the kerberos server's IP address must be set!

| username and password
| this allows they kerberos ticket encryption type to be set with the `etype` parameter

.. code:: python

	'ldap+kerberos-password://TEST\\victim:Passw0rd!1@10.10.10.2/?dc=10.10.10.2'
.. code:: python

	'ldap+kerberos-password://TEST\\victim:Passw0rd!1@10.10.10.2/?dc=10.10.10.2&etype=23'

| RC4 key (same as NT hash)

.. code:: python

	'ldap+kerberos-rc4://TEST\\victim:f8963568a1ec62a3161d9d6449baba93@10.10.10.2/?dc=10.10.10.2'

| AES key (both 128 and 256 bits supported)

.. code:: python

	'ldap+kerberos-aes://TEST\\victim:XXXXX@10.10.10.2/?dc=10.10.10.2'

| SSPI integrated auth. 
| This will use the current user's authentication context. 
| The username doesn't matter, but the correct domain must be set! Windows only 

.. code:: python

	'ldap+sspi-kerberos://TEST\\victim@10.10.10.2/?dc=10.10.10.2'


Anonymous Bind
--------------------
| Currently only the `simple bind` provides anonymous auth

.. code:: python

	'ldap+simple://10.10.10.2'


Connection
"""""""""""""""
Various connection options available. Most of them are listed below.

LDAPS
--------------------
| LDAP-over-SSL can be selected by replacing the `ldap` specification in the `url` parameter with `ldaps`

.. warning:: For a successful connection over LDAPS the proper hostname of the server must be used!

.. code:: python

	'ldaps+simple://dc1.test.corp'

Channel Binding
--------------------
| When LDAPS is used, the module automatically performs channel binding. No additional changes necessary

Encryption
--------------------
| When GSSAPI authentication is used, the encryption can be turned on to provide more security.
| This is done by the `encrypt` parameter added to the `url`.
| It is not enabled by default, as it can slow down the connection considerably. 

.. warning:: Channel encryption MUST NOT be used together with LDAPS! Doing so will result in failed connection! (this limitation is in the server implementation, not in msldap)

.. code:: python

	'ldap+ntlm-password://TEST\\victim:Passw0rd!1@10.10.10.2/?encrypt=1'