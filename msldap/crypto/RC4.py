"""
The idea here is to offer compatibility with 3rd party libraries by extending wrappers for ech encryption mode
This is needed because the pure python implementation for encryption and hashing algorithms are quite slow

currently it's not the perfect wrapper, needs to be extended
"""

from aiosmb.crypto.BASE import symmetricBASE, cipherMODE
from aiosmb.crypto.pure.RC4.RC4 import RC4 as _pureRC4
try:
	from Crypto.Cipher import ARC4 as _pyCryptoRC4
except Exception as e:
	#print(e)
	pass

try:
	from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
	from cryptography.hazmat.backends import default_backend
except:
	pass

class pureRC4(symmetricBASE):
	def __init__(self, key):
		if not isinstance(key, bytes):
			raise Exception('Key needs to be bytes!')
		self.key = key
		symmetricBASE.__init__(self)
		
	def setup_cipher(self):		
		self._cipher = _pureRC4(self.key)

	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)

class pyCryptoRC4(symmetricBASE):
	def __init__(self, key):
		self.key = key
		symmetricBASE.__init__(self)
		
	def setup_cipher(self):
		self._cipher = _pyCryptoRC4.new(self.key)
		
	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)

class cryptographyRC4(symmetricBASE):
	def __init__(self, key):
		if not isinstance(key, bytes):
			raise Exception('Key needs to be bytes!')
		self.key = key
		self.encryptor = None
		self.decryptor = None
		symmetricBASE.__init__(self)

	def setup_cipher(self):
		algorithm = algorithms.ARC4(self.key)
		self._cipher = Cipher(algorithm, mode=None, backend=default_backend())
		self.encryptor = self._cipher.encryptor()
		self.decryptor = self._cipher.decryptor()

	def encrypt(self, data):
		return self.encryptor.update(data)
	def decrypt(self, data):
		return self.decryptor.update(data)