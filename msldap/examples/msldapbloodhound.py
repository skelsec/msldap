import asyncio
from msldap.bloodhound import MSLDAPDump2Bloodhound

async def amain(url, follow_trusts):
	msldap = MSLDAPDump2Bloodhound(url, follow_trusts=follow_trusts)
	await msldap.run()

def main():
	import argparse
	parser = argparse.ArgumentParser(description='Bloodhound collector for MSLDAP')
	parser.add_argument('url', help='LDAP connection URL, or ADEXPLORER dat file path in the form adexplorer://<path>')
	parser.add_argument('--follow-trusts', action='store_true', help='Follow trusts')
	print("""
WARNING: This script is still in development. It is not guaranteed to provide the same results as the original Bloodhound collector.
""")
	args = parser.parse_args()
	asyncio.run(amain(args.url, args.follow_trusts))

if __name__ == '__main__':
	main()
