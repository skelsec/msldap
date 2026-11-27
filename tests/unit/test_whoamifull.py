"""Offline tests for MSLDAPClient.whoamifull error handling."""

import pytest

from msldap.client import MSLDAPClient

D = 'S-1-5-21-1-2-3'
USER = D + '-1105'
DU = D + '-513'
GRP = D + '-1200'


class _User:
	objectSid = USER
	distinguishedName = 'CN=john,DC=corp,DC=local'


class FakeClient(MSLDAPClient):
	def __init__(self, whoami_res = 'u:CORP\\john', user = _User(), user_err = None, tg_err = None, resolv_fail = ()):
		self._whoami_res = whoami_res
		self._user = user
		self._user_err = user_err
		self._tg_err = tg_err
		self._resolv_fail = set(resolv_fail)
		self.looked_up = None

	async def whoami(self):
		return self._whoami_res, None

	async def get_user(self, samaccountname):
		self.looked_up = samaccountname
		return self._user, self._user_err

	async def get_tokengroups(self, dn):
		yield USER, None # own SID first, like the real implementation
		yield DU, None
		if self._tg_err is not None:
			yield None, self._tg_err
			return
		yield GRP, None

	async def resolv_sid(self, sid, use_cache = True):
		if sid in self._resolv_fail:
			return None, None, Exception('resolve failed')
		return 'CORP', 'name-%s' % sid, None


async def test_happy_path_no_duplicate_own_sid():
	res, err = await FakeClient().whoamifull()
	assert err is None
	assert res['sid'] == USER
	assert res['tokengroups'] == [USER, DU, GRP]
	assert res['domain'] == 'CORP' and res['samaccountname'] == 'john'
	assert USER in res['groups'] # unchanged: own SID is still listed in groups

async def test_tokengroups_error_is_returned():
	res, err = await FakeClient(tg_err = Exception('ldap error')).whoamifull()
	assert err is not None
	assert res['tokengroups'] == [USER, DU] # partial result kept

async def test_get_user_error_is_returned():
	res, err = await FakeClient(user_err = Exception('ldap error')).whoamifull()
	assert err is not None

async def test_user_not_found_is_not_an_error():
	res, err = await FakeClient(user = None).whoamifull()
	assert err is None
	assert 'sid' not in res

async def test_anonymous_is_not_an_error():
	res, err = await FakeClient(whoami_res = '').whoamifull()
	assert err is None
	assert res['tokengroups'] == []

async def test_resolve_failure_keeps_remaining_groups():
	res, err = await FakeClient(resolv_fail = [DU]).whoamifull()
	assert err is None
	assert res['tokengroups'] == [USER, DU, GRP]
	assert res['groups'][DU] == ('NA', 'NA')

@pytest.mark.parametrize('raw, name, domain', [
	('u:CORP\\john', 'john', 'CORP'),
	('u:john@corp.local', 'john', 'corp.local'),
	('u:john', 'john', None),
])
async def test_identity_formats(raw, name, domain):
	c = FakeClient(whoami_res = raw)
	res, err = await c.whoamifull()
	assert err is None
	assert c.looked_up == name and res['domain'] == domain
