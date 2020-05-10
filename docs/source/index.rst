.. msldap documentation master file, created by
   sphinx-quickstart on Sat May  9 03:33:11 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.
   , get_dn_for_objectsid, get_group_members

Welcome to msldap's documentation!
==================================

Basic example
----------------------------
| All basic examples will fetch the user object of the user `Administrator` and print out the attributes
| The difference is the type of authentication and security settings which are controlled by the `url` parameter
|
| This module supports a wide variety of authentication and channel protection mechanisms, check the Tutorials! 

.. literalinclude:: ../../examples/client.py
   :emphasize-lines: 4


Tutorials
---------

.. toctree::
   :maxdepth: 2

   tutorial

API Reference
--------------

.. toctree::
   :maxdepth: 2

   api