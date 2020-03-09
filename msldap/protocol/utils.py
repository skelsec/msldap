

def calcualte_length(data):
	"""
	LDAP protocol doesnt send the total length of the message in the header,
	it only sends raw ASN1 encoded data structures, which has the length encoded.
	This function "decodes" the length os the asn1 structure, and returns it as int.
	"""
	if data[1] <= 127:
		return data[1] + 2
	else:
		bcount = data[1] - 128
		#if (bcount +2 ) > len(data):
		#	raise Exception('LDAP data too larage! Length byte count: %s' % bcount)
		return int.from_bytes(data[2:2+bcount], byteorder = 'big', signed = False) + bcount + 2

