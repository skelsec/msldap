"""
The idea here is to offer compatibility with 3rd party libraries by extending wrappers for ech encryption mode
This is needed because the pure python implementation for encryption and hashing algorithms are quite slow

currently it's not the perfect wrapper, needs to be extended
"""

from msldap.crypto.BASE import symmetricBASE, cipherMODE
from msldap.crypto.pure.AES import AESModeOfOperationECB, AESModeOfOperationCBC, AESModeOfOperationCTR
try:
	from Crypto.Cipher import AES as _pyCryptoAES
except:
	pass

try:
	from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
	from cryptography.hazmat.primitives import padding
	from cryptography.hazmat.backends import default_backend
except:
	pass

class pureAES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, pad = None, padMode = None):
		self.key = key
		self.mode = mode
		self.IV = IV
		self.pad = pad
		self.padMode = padMode

		symmetricBASE.__init__(self)

	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = AESModeOfOperationECB(self.key)
		elif self.mode == cipherMODE.CBC:
			self._cipher = AESModeOfOperationCBC(self.key, iv = self.IV)
		elif self.mode == cipherMODE.CTR:
			self._cipher = AESModeOfOperationCTR(self.key, iv = self.IV)
		else:
			raise Exception('Unknown cipher mode!')

	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)

class pyCryptoAES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, pad = None, padMode = None):
		self.key = key
		self.mode = mode
		self.IV = IV
		self.pad = pad
		self.padMode = padMode

		symmetricBASE.__init__(self)
		
	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = _pyCryptoAES.new(self.key, _pyCryptoAES.MODE_ECB)
		
		elif self.mode == cipherMODE.CBC:
			self._cipher = _pyCryptoAES.new(self.key, _pyCryptoAES.MODE_CBC, self.IV)
		elif self.mode == cipherMODE.CTR:
			self._cipher = _pyCryptoAES.new(self.key, _pyCryptoAES.MODE_CTR, self.IV)
		else:
			raise Exception('Unknown cipher mode!')
		
	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)

class cryptographyAES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None, pad = None, padMode = None):
		self.IV = IV
		#the python cryptography module sets the IV in the operational mode!!!
		if mode == cipherMODE.ECB:
			self.IV = modes.ECB()
		elif mode == cipherMODE.CBC:
			self.IV = modes.CBC(IV)
		elif mode == cipherMODE.CBC:
			self.IV = modes.CTR(IV)
		else:
			raise Exception('Unknown cipher mode!')
		
		self.key = key
		
		""" TODO padding
		if self.padMode is not None:
		"""
		
		self.encryptor = None
		self.decryptor = None
		symmetricBASE.__init__(self)

	def setup_cipher(self):
		algorithm = algorithms.AES(self.key)
		self._cipher = Cipher(algorithm, mode=self.IV, backend=default_backend())
		self.encryptor = self._cipher.encryptor()
		self.decryptor = self._cipher.decryptor()

	def encrypt(self, data):
		return self.encryptor.update(data)
	

	def decrypt(self, data):
		return self.decryptor.update(data)
