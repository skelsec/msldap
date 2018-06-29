import logging
import csv
from msldap.core.msldap import UserCredential, TargetServer, MSLDAP
from msldap.ldap_objects.aduser import MSADUser


if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG)
	creds = UserCredential(username = 'TEST\\victim', password = 'Almaalmaalma!1')
	target = TargetServer('dc=TEST,dc=corp', '192.168.9.1')

	print(creds.get_msuser())

	ldap = MSLDAP(creds, target)
	print(ldap.get_server_info())

	ldap.connect()

	adinfo = ldap.get_ad_info()
	print(adinfo)

	csv.register_dialect('tsv', delimiter='\t', quoting=csv.QUOTE_NONE)
	with open('example2.csv', 'w') as f:
		writer = csv.writer(f, 'tsv')
		writer.writerow(MSADUser.TSV_ATTRS)
		for user in ldap.get_all_user_objects():
			writer.writerow(user.get_row(MSADUser.TSV_ATTRS))
