
MSADIssuancePolicy_ATTRS = ['cn', 'distinguishedName', 'name', 'displayName', 'flags', 'msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink']

class MSADIssuancePolicy:
	"""msPKI-Enterprise-Oid object under CN=OID,CN=Public Key Services. flags == 2 marks an issuance policy."""
	def __init__(self):
		self.cn = None
		self.distinguishedName = None
		self.name = None
		self.displayName = None
		self.flags = None
		self.oid = None
		self.group_link = None # DN of the group linked via msDS-OIDToGroupLink (ESC13)

	@staticmethod
	def from_ldap(entry):
		adi = MSADIssuancePolicy()
		adi.cn = entry['attributes'].get('cn')
		adi.distinguishedName = entry['attributes'].get('distinguishedName')
		adi.name = entry['attributes'].get('name')
		adi.displayName = entry['attributes'].get('displayName')
		adi.flags = entry['attributes'].get('flags')
		adi.oid = entry['attributes'].get('msPKI-Cert-Template-OID')
		adi.group_link = entry['attributes'].get('msDS-OIDToGroupLink')
		return adi

	def to_dict(self):
		return {
			'cn' : self.cn,
			'distinguishedName' : self.distinguishedName,
			'name' : self.name,
			'displayName' : self.displayName,
			'flags' : self.flags,
			'oid' : self.oid,
			'group_link' : self.group_link,
		}

	def __str__(self):
		t = '== MSADIssuancePolicy ==\r\n'
		t += 'Name: %s\r\n' % self.displayName
		t += 'OID: %s\r\n' % self.oid
		t += 'Linked group: %s\r\n' % self.group_link
		return t
