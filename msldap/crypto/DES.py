"""
The idea here is to offer compatibility with 3rd party libraries by extending wrappers for ech encryption mode
This is needed because the pure python implementation for encryption and hashing algorithms are quite slow

currently it's not the perfect wrapper, needs to be extended
"""

from msldap.crypto.BASE import symmetricBASE, cipherMODE
import msldap.crypto.pure.DES.DES as _pyDES
try:
	from Crypto.Cipher import DES as _pyCryptoDES
except:
	pass

try:
	from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
	from cryptography.hazmat.backends import default_backend
except:
	pass


# from impacket
def expand_DES_key(key):
	# Expand the key from a 7-byte password key into a 8-byte DES key
	key  = key[:7]
	key += b'\x00'*(7-len(key))
	s  = (((key[0] >> 1) & 0x7f) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1).to_bytes(1, byteorder = 'big')
	s += (((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1).to_bytes(1, byteorder = 'big')
	s += ( (key[6] & 0x7f) << 1).to_bytes(1, byteorder = 'big')
	return s
#

class pureDES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None):
		self.key = key
		if len(key) == 7:
			self.key = expand_DES_key(key)

		self.mode = mode
		self.IV = IV
		symmetricBASE.__init__(self)

	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			mode = _pyDES.ECB
		elif self.mode == cipherMODE.CBC:
			mode = _pyDES.CBC
		else:
			raise Exception('Unknown cipher mode!')
		
		self._cipher = _pyDES.des(self.key, mode, self.IV)

	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)



class pyCryptoDES(symmetricBASE):
	def __init__(self, key, mode = cipherMODE.ECB, IV = None):
		self.key = key
		if len(key) == 7:
			self.key = __expand_DES_key(key)

		self.mode = mode
		self.IV = IV
		symmetricBASE.__init__(self)

	def setup_cipher(self):
		if self.mode == cipherMODE.ECB:
			self._cipher = _pyCryptoDES.new(self.key)
		elif self.mode == cipherMODE.CBC:
			self._cipher = _pyCryptoDES.new(self.key, _pyCryptoDES.MODE_CBC, self.IV)
		else:
			raise Exception('Unknown cipher mode!')
		
		

	def encrypt(self, data):
		return self._cipher.encrypt(data)
	def decrypt(self, data):
		return self._cipher.decrypt(data)

