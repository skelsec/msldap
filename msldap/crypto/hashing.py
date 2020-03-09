import hashlib
import hmac

from aiosmb.crypto.BASE import hashBASE, hmacBASE

class md5(hashBASE):
	def __init__(self, data = None):
		hashBASE.__init__(self, data)
	def setup_hash(self):
		self._hash = hashlib.new('md5')
	def update(self, data):
		return self._hash.update(data)
	def digest(self):
		return self._hash.digest()
	def hexdigest(self):
		return self._hash.hexdigest()

class md4(hashBASE):
	def __init__(self, data = None):
		hashBASE.__init__(self, data)
	def setup_hash(self):
		self._hash = hashlib.new('md4')
	def update(self, data):
		return self._hash.update(data)
	def digest(self):
		return self._hash.digest()
	def hexdigest(self):
		return self._hash.hexdigest()

class hmac_md5(hmacBASE):
	def __init__(self, key):
		hmacBASE.__init__(self, key)
	def setup_hash(self):
		self._hmac = hmac.new(self._key, digestmod = hashlib.md5)
	def update(self, data):
		return self._hmac.update(data)
	def digest(self):
		return self._hmac.digest()
	def hexdigest(self):
		return self._hmac.hexdigest()	

class sha256():
	def __init__(self, data = None):
		hashBASE.__init__(self, data)
	def setup_hash(self):
		self._hash = hashlib.new('sha256')
	def update(self, data):
		return self._hash.update(data)
	def digest(self):
		return self._hash.digest()
	def hexdigest(self):
		return self._hash.hexdigest()	