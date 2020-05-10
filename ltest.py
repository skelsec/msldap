import logging
import asyncio
from msldap.commons.url import MSLDAPURLDecoder

url = 'ldap+simple://10.10.10.2'

async def client(url):
	try:
		conn_url = MSLDAPURLDecoder(url)
		conn = conn_url.get_connection()
		_, err = await conn.connect()
		if err is not None:
			print('logon failed!')
			raise err
		
		res, err = await conn.get_serverinfo()
		print(str(res))

	except:
		logging.exception('err!')

if __name__ == '__main__':	
	asyncio.run(client(url))
