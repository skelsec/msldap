import importlib
import importlib.util

#
##key = name of the cipher, value=list of module names, in order of preference
#preftable = {
#	'DES' : ['pyCrypto','pure'], 
#	'TDES': ['pyCrypto','pure'], 
#	'AES' : ['cryptography','pyCrypto','pure'], 
#	'RC4' : ['cryptography','pyCrypto','pure'],
#
#}
#
#available_modules = ['pure']
#
#if importlib.util.find_spec("cryptography") is not None:
#	#print('Found cryptography package!')
#	available_modules.append("cryptography")
#
#elif importlib.util.find_spec("pyCrypto") is not None:
#	#print('Found cryptography package!')
#	available_modules.append("pyCrypto")
#
#
##https://stackoverflow.com/questions/8790003/dynamically-import-a-method-in-a-file-from-a-string
#def import_from(module, name):
#	module = __import__(module, fromlist=[name])
#	return getattr(module, name)
#
#
#def getPreferredCipher(cipherName):
#	if cipherName not in preftable:
#		raise Exception('Cipher %s doesnt have any preferences set!' % cipherName)
#	possible_prefmodule = list(set(preftable[cipherName]).intersection(set(available_modules)))
#	selected_module = None
#	for moduleName in preftable[cipherName]:
#		if moduleName in possible_prefmodule:
#			selected_module = moduleName
#
#	if selected_module is None:
#		raise Exception('Could not find any modules to load cipher %s' % cipherName)
#
#
#	#print('Preferred module selected for cipher %s is %s' % (cipherName, selected_module))
#	moduleName = 'aiosmb.crypto.%s' % cipherName
#	objectName = selected_module + cipherName
#	return import_from(moduleName , objectName)
#
#def getSpecificCipher(cipherName, moduleBaseName):
#	moduleName = 'aiosmb.crypto.%s' % cipherName
#	objectName = '%s%s' % (moduleBaseName, cipherName)
#	return import_from(moduleName , objectName)


#import ciphers
# TODO: fix the dynamic imports, currently only supporting pure-python ciphers for two reasons:
# 1. dynamic import messes up some scripts like pyinstaller/nuitka/py2exe
# 2. additional effort needed to support more crypto libs anyhow

from msldap.crypto.AES import pureAES
from msldap.crypto.RC4 import pureRC4
from msldap.crypto.DES import pureDES

DES  = pureDES #getPreferredCipher('DES')
AES  = pureAES #getPreferredCipher('AES')
RC4  = pureRC4 #getPreferredCipher('RC4')
#TDES = getPreferredCipher('TDES')
