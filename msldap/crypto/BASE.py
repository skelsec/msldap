from abc import ABC, abstractmethod
import enum

class cipherMODE(enum.Enum):
	ECB = enum.auto()
	CBC = enum.auto()
	CTR = enum.auto()

class symmetricBASE():
	def __init__(self):
		self._cipher = None
		self.setup_cipher()

	@abstractmethod
	def setup_cipher(self):
		#create the hash object here
		pass

	@abstractmethod
	def encrypt(self, data):
		pass

	@abstractmethod
	def decrypt(self):
		pass

class hashBASE():
	def __init__(self, data):
		self._hash = None
		self.setup_hash()

		if data is not None:
			self._hash.update(data)

	@abstractmethod
	def setup_hash(self):
		#create the hash object here
		pass

	@abstractmethod
	def update(self, data):
		pass

	@abstractmethod
	def digest(self):
		pass

	@abstractmethod
	def hexdigest(self):
		pass

class hmacBASE():
	def __init__(self, key):
		self._key = key
		self._hash = None
		self.setup_hash()

	@abstractmethod
	def setup_hash(self):
		#create the hash object here
		pass

	@abstractmethod
	def update(self, data):
		pass

	@abstractmethod
	def digest(self):
		pass

	@abstractmethod
	def hexdigest(self):
		pass