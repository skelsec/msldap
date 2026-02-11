from typing import List, Any, Type

# This class is used to encode custom values to LDAP
# HOW TO USE -for encoding-:
# 1. Implement your class and inherit from LDAPCustomValue
# 2. Implement the encode method
# 3. No need to register the class before using it.
# 4. When performing an LDAP modify operation, if the attribute value is an instance of your class, it will be encoded automatically.
#
# HOW TO USE -for decoding-:
# 1. Implement your class and inherit from LDAPCustomValue
# 2. Implement the decode method
# 3. Register the class using register_custom_attribute_type
# 4. When performing an LDAP query, if the attribute type is registered, the attribute value will be decoded automatically.


class LDAPCustomValue:
	def __init__(self, value = None):
		self.value = value

	def encode(self) -> List[bytes]:
		"""
		Override this method to encode the value to a list of bytes.
		This method MUST return a list of bytes.
		"""
		raise NotImplementedError()

	@staticmethod
	def decode(value: List[bytes]) -> Any:
		"""
		Override this method to decode the value from a list of bytes.
		This method MUST return a value.
		The value to be decoded is always alist of bytes.
		"""
		raise NotImplementedError()

def register_custom_attribute_type(name: str, custom_value_class: Type[LDAPCustomValue]):
	"""
	Registers a custom attribute type for decoding.
	"""
	from msldap.protocol.typeconversion import MSLDAP_CUSTOM_ATTRIBUTE_TYPES

	if name in MSLDAP_CUSTOM_ATTRIBUTE_TYPES:
		raise Exception('Custom attribute type "%s" already registered' % name)
	MSLDAP_CUSTOM_ATTRIBUTE_TYPES[name] = custom_value_class