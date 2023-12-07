import asyncio
from msldap.bloodhound import MSLDAPDump2Bloodhound

async def amain():
	args = parser.parse_args()
	msldap = MSLDAPDump2Bloodhound(args.url)
	await msldap.run()

if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser(description='Bloodhound collector for MSLDAP')
	parser.add_argument('url', help='LDAP connection URL, or ADEXPLORER dat file path in the form adexplorer://<path>')
	print("""
WARNING: This script is still in development. It is not guaranteed to provide the same results as the original Bloodhound collector.
""")
	asyncio.run(amain())
