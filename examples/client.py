import asyncio
from msldap.commons.factory import LDAPConnectionFactory

url = 'ldap+simple://TEST\\victim:Passw0rd!1@10.10.10.2'

async def client(url):
	conn_url = LDAPConnectionFactory.from_url(url)
	ldap_client = conn_url.get_client()
	_, err = await ldap_client.connect()
	if err is not None:
		raise err

	user = await ldap_client.get_user('Administrator')
	print(str(user))

if __name__ == '__main__':	
	asyncio.run(client(url))
