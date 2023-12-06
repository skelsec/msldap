


def reverse_dn_components(dn:str):
	rdns = ','.join(reversed(dn.split(',')))
	return rdns.upper()

def explode_dn(dn):
	parts = []
	esc = False
	part = ''

	for char in dn:
		if esc:
			part += char
			esc = False
		elif char == '\\':
			esc = True
			part += char
		elif char == ',':
			if part:
				parts.append(part)
				part = ''
		else:
			part += char

	if part:
		parts.append(part)

	return parts


def parse_gplink_string(linkstr):
	if not linkstr:
		return
	for links in linkstr.split('[LDAP://')[1:]:
		dn, options = links.rstrip('][').split(';')
		yield dn, int(options)



#taken from bloodhound.py
def is_filtered_container(containerdn):
	if "CN=DOMAINUPDATES,CN=SYSTEM,DC=" in containerdn.upper():
		return True
	if "CN=POLICIES,CN=SYSTEM,DC=" in containerdn.upper() and (containerdn.upper().startswith('CN=USER') or containerdn.upper().startswith('CN=MACHINE')):
		return True
	return False

def is_filtered_container_child(containerdn):
	if "CN=PROGRAM DATA,DC=" in containerdn.upper():
		return True
	if "CN=SYSTEM,DC=" in containerdn.upper():
		return True
	return False