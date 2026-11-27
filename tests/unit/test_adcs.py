"""Offline tests for the ADCS analysis engine (msldap.commons.adcs) and MSADCertificateTemplate."""

import pytest
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

from msldap.commons.adcs import (
	ACLModel, PrincipalSet, analyze_pki_object, analyze_templates,
	EX_RIGHT_CERTIFICATE_ENROLLMENT,
)
from msldap.ldap_objects.adcertificatetemplate import (
	MSADCertificateTemplate, EKU_CLIENT_AUTHENTICATION_OID, EKU_ANY_PURPOSE_OID,
	EKU_CERTIFICATE_REQUEST_AGENT_OID, EKU_SERVER_AUTHENTICATION_OID,
)

D = 'S-1-5-21-1-2-3'
DA = D + '-512'
DU = D + '-513'
DC = D + '-515'
USER = D + '-1105'
EKU_SERVER_AUTH = '1.3.6.1.5.5.7.3.1'
NAME_FLAG_GUID = 'ea1dddc4-60ff-416e-8cc0-17cee534bce7'
DANGEROUS = {NAME_FLAG_GUID: 'msPKI-Certificate-Name-Flag'}

ENROLL_DU = '(OA;;CR;%s;;%s)' % (EX_RIGHT_CERTIFICATE_ENROLLMENT, DU)
ADMIN_FULL = '(A;;0xf01ff;;;%s)' % DA


def sd(aces, owner = DA):
	return SECURITY_DESCRIPTOR.from_sddl('O:%sG:%sD:%s%s' % (owner, DA, ADMIN_FULL, aces))

def template(aces = ENROLL_DU, owner = DA, name_flag = 0, enrollment_flag = 0, ra_signature = 0,
		ekus = (EKU_CLIENT_AUTHENTICATION_OID,), schema = 2, ra_policies = None, cert_policies = None):
	entry = {'attributes': {
		'name': 'TestTemplate',
		'distinguishedName': 'CN=TestTemplate,CN=Certificate Templates',
		'msPKI-Certificate-Name-Flag': name_flag,
		'msPKI-Enrollment-Flag': enrollment_flag,
		'msPKI-RA-Signature': ra_signature,
		'msPKI-Template-Schema-Version': schema,
		'msPKI-RA-Application-Policies': list(ra_policies or []),
		'msPKI-Certificate-Policy': list(cert_policies or []),
		'pKIExtendedKeyUsage': list(ekus),
		'nTSecurityDescriptor': sd(aces, owner).to_bytes(),
	}}
	t = MSADCertificateTemplate.from_ldap(entry)
	t.enroll_services = ['ca.corp.local\\CORP-CA']
	return t

def escs(t, psets = None, **kw):
	if psets is None:
		psets = [PrincipalSet.lowpriv(D)]
	return {f.esc for f in t.analyze(psets, **kw)}


class TestEnrollmentRights:
	def test_esc1_via_enroll_right(self):
		assert 'ESC1' in escs(template(name_flag = 1))

	def test_esc1_via_all_extended_rights(self):
		assert 'ESC1' in escs(template('(A;;0x100;;;%s)' % DU, name_flag = 1))

	def test_esc1_via_generic_all_generic_bit(self):
		res = escs(template('(A;;GA;;;%s)' % DU, name_flag = 1))
		assert 'ESC1' in res and 'ESC4' in res

	def test_deny_enroll_wins(self):
		aces = ENROLL_DU + '(OD;;CR;%s;;%s)' % (EX_RIGHT_CERTIFICATE_ENROLLMENT, 'S-1-5-11')
		assert 'ESC1' not in escs(template(aces, name_flag = 1))

	def test_inherit_only_ace_ignored(self):
		assert 'ESC4' not in escs(template(ENROLL_DU + '(A;IO;0xf01ff;;;%s)' % DU))

	def test_current_user_gets_everyone_and_authusers(self):
		t = template('(OA;;CR;%s;;S-1-5-11)' % EX_RIGHT_CERTIFICATE_ENROLLMENT, name_flag = 1)
		# tokenGroups never contains Authenticated Users, it must still match
		assert 'ESC1' in escs(t, [PrincipalSet.current_user([USER])])

	def test_domain_computers_set(self):
		t = template('(OA;;CR;%s;;%s)' % (EX_RIGHT_CERTIFICATE_ENROLLMENT, DC), name_flag = 1)
		assert 'ESC1' not in escs(t)
		assert 'ESC1' in escs(t, [PrincipalSet.domain_computers(D, 10)])

	def test_no_enroll_no_findings(self):
		assert escs(template('', name_flag = 1)) == set()


class TestBlockers:
	def test_manager_approval_blocks_esc1(self):
		assert 'ESC1' not in escs(template(name_flag = 1, enrollment_flag = 0x2))

	def test_authorized_signature_blocks_esc1(self):
		assert 'ESC1' not in escs(template(name_flag = 1, ra_signature = 1))

	def test_legacy_is_vulnerable2_respects_manager_approval(self):
		t = template(name_flag = 1, enrollment_flag = 0x2)
		assert 'ESC1' not in t.is_vulnerable2([DU])


class TestESCs:
	def test_esc2_no_eku_and_any_purpose(self):
		assert 'ESC2' in escs(template(ekus = ()))
		assert 'ESC2' in escs(template(ekus = (EKU_ANY_PURPOSE_OID,)))
		assert 'ESC2' not in escs(template())

	def test_esc3_agent(self):
		assert 'ESC3' in escs(template(ekus = (EKU_CERTIFICATE_REQUEST_AGENT_OID,)))

	def test_esc3_target_v1(self):
		assert 'ESC3-TARGET' in escs(template(schema = 1))

	def test_esc3_target_v2_requires_ra_policy(self):
		assert 'ESC3-TARGET' in escs(template(schema = 2, ra_signature = 1, ra_policies = [EKU_CERTIFICATE_REQUEST_AGENT_OID]))
		assert 'ESC3-TARGET' not in escs(template(schema = 2, ra_signature = 1, ra_policies = []))
		assert 'ESC3-TARGET' not in escs(template(schema = 2))

	def test_esc9(self):
		assert 'ESC9' in escs(template(enrollment_flag = 0x80000))
		assert 'ESC9' not in escs(template(enrollment_flag = 0x80000, ekus = (EKU_SERVER_AUTH,)))

	def test_esc13(self):
		t = template(cert_policies = ['1.2.3.4'])
		assert 'ESC13' in escs(t, linked_issuance_policies = {'1.2.3.4': 'CN=Admins'})
		assert 'ESC13' not in escs(t, linked_issuance_policies = {'9.9.9': 'CN=Admins'})

	def test_esc15_without_client_auth(self):
		res = escs(template(schema = 1, name_flag = 1, ekus = (EKU_SERVER_AUTH,)))
		assert 'ESC15' in res and 'ESC1' not in res


class TestESC4:
	def test_owner(self):
		assert 'ESC4' in escs(template(owner = DU))

	def test_specific_property_write(self):
		t = template(ENROLL_DU + '(OA;;WP;%s;;%s)' % (NAME_FLAG_GUID, DU))
		assert 'ESC4' in escs(t, dangerous_guids = DANGEROUS)
		assert 'ESC4' not in escs(t, dangerous_guids = {'00000000-0000-0000-0000-000000000000': 'x'})
		assert 'ESC4' in escs(t, dangerous_guids = None) # unresolved: reported

	def test_write_dacl_without_enroll(self):
		assert 'ESC4' in escs(template('(A;;0x40000;;;%s)' % DU))


class TestLegacyAPI:
	def test_legacy_sid_sets(self):
		t = template('(A;;0x100;;;%s)' % DU)
		assert DU in t.allextendedrights_sids
		assert DA in t.fullcontrol_sids

	def test_is_vulnerable_tuple(self):
		ok, reason = template(name_flag = 1).is_vulnerable()
		assert ok is True and 'ESC1' in reason
		assert template('').is_vulnerable() == (False, 'No match found')

	def test_enrollment_services_without_backslash(self):
		t = template()
		t.enroll_services = ['CORP-CA']
		assert t.enrollment_services == [(None, 'CORP-CA')]

	def test_missing_flags_do_not_crash(self):
		t = template()
		t.Enrollment_Flag = None
		t.Certificate_Name_Flag = None
		t.pKIExtendedKeyUsage = None
		assert t.requires_manager_approval() is False
		assert t.allows_to_specify_san() is False
		assert t.can_be_used_for_any_purpose() is True


class TestESC5:
	def test_container_generic_all(self):
		s = sd('(A;;0xf01ff;;;%s)' % DU)
		assert len(analyze_pki_object('PKS', 'CN=PKS', s, [PrincipalSet.lowpriv(D)])) == 1

	def test_create_child_only_when_dangerous(self):
		s = sd('(A;;0x1;;;%s)' % DU)
		assert analyze_pki_object('X', 'CN=X', s, [PrincipalSet.lowpriv(D)]) == []
		assert len(analyze_pki_object('Certificate Templates', 'CN=X', s, [PrincipalSet.lowpriv(D)], allow_create_child = True)) == 1

	def test_admin_only_acl(self):
		assert analyze_pki_object('X', 'CN=X', sd(''), [PrincipalSet.lowpriv(D)]) == []


def test_aclmodel_none_sd():
	acl = ACLModel(None)
	assert acl.evaluate([DU]).can_enroll is False


class _FakeInfo:
	objectSid = D
	machineAccountQuota = 10
	distinguishedName = 'DC=corp,DC=local'

def _make_fake_client():
	from msldap.client import MSLDAPClient
	cfg = 'CN=Configuration,DC=corp,DC=local'
	pks = 'CN=Public Key Services,CN=Services,%s' % cfg
	tmpl_esc1 = template(name_flag = 1).nTSecurityDescriptor.to_bytes()
	tmpl_dc = sd('(OA;;CR;%s;;%s)' % (EX_RIGHT_CERTIFICATE_ENROLLMENT, DC)).to_bytes()
	tmpl_wp = sd(ENROLL_DU + '(OA;;WP;%s;;%s)' % (NAME_FLAG_GUID, DU)).to_bytes()

	def tmpl(name, sdbytes, name_flag = 1, policies = None):
		return {'attributes': {
			'name': name, 'distinguishedName': 'CN=%s,CN=Certificate Templates,%s' % (name, pks),
			'msPKI-Certificate-Name-Flag': name_flag, 'msPKI-Enrollment-Flag': 0, 'msPKI-RA-Signature': 0,
			'msPKI-Template-Schema-Version': 2, 'pKIExtendedKeyUsage': [EKU_CLIENT_AUTHENTICATION_OID],
			'msPKI-Certificate-Policy': policies or [], 'nTSecurityDescriptor': sdbytes,
		}}

	data = {
		'(objectCategory=pKIEnrollmentService)': [{'attributes': {
			'name': 'CORP-CA', 'dNSHostName': 'ca.corp.local', 'certificateTemplates': ['ESC1', 'DCOnly', 'PropWrite', 'Linked'],
		}}],
		'(objectClass=msPKI-Enterprise-Oid)': [{'attributes': {
			'msPKI-Cert-Template-OID': '1.2.3.4', 'msDS-OIDToGroupLink': 'CN=Admins,DC=corp,DC=local',
		}}],
		'(objectCategory=pKICertificateTemplate)': [
			tmpl('ESC1', tmpl_esc1),
			tmpl('DCOnly', tmpl_dc),
			tmpl('PropWrite', tmpl_wp, name_flag = 0),
			tmpl('Linked', sd(ENROLL_DU).to_bytes(), name_flag = 0, policies = ['1.2.3.4']),
		],
	}
	pki_objects = {
		(pks, 0): [{'attributes': {'name': 'Public Key Services', 'distinguishedName': pks, 'nTSecurityDescriptor': sd('').to_bytes()}}],
		(pks, 1): [{'attributes': {'name': 'Certificate Templates', 'distinguishedName': 'CN=Certificate Templates,' + pks, 'nTSecurityDescriptor': sd('(A;;0x1;;;%s)' % DU).to_bytes()}}],
		('CN=Enrollment Services,' + pks, 1): [],
	}

	class FakeClient(MSLDAPClient):
		def __init__(self):
			self._ldapinfo = _FakeInfo()
			self._serverinfo = {'configurationNamingContext': cfg, 'schemaNamingContext': 'CN=Schema,' + cfg}
			self.searches = []
			self.whoami_res = 'u:CORP\\john'

		async def whoami(self):
			return self.whoami_res, None

		async def get_tokengroups_user(self, samaccountname):
			if samaccountname != 'john':
				return None, Exception('User not found! %s' % samaccountname)
			return [USER, DU], None

		async def pagedsearch(self, query, attributes, controls = None, tree = None, search_scope = 2):
			self.searches.append((query, tree))
			if query.startswith('(|(lDAPDisplayName='):
				yield {'attributes': {'lDAPDisplayName': 'msPKI-Certificate-Name-Flag', 'schemaIDGUID': NAME_FLAG_GUID}}, None
				return
			if query == '(objectClass=*)':
				for e in pki_objects.get((tree, search_scope), []):
					yield e, None
				return
			for e in data.get(query, []):
				yield e, None

	return FakeClient()

@pytest.mark.asyncio
async def test_audit_adcs_end_to_end():
	client = _make_fake_client()
	findings = []
	async for finding, err in client.audit_adcs():
		assert err is None, err
		findings.append(finding)
	got = {(f.esc, f.object_name, f.principal_set.label) for f in findings}
	assert ('ESC1', 'ESC1', 'current-user') in got
	assert ('ESC1', 'ESC1', 'low-priv') in got
	assert ('ESC1', 'DCOnly', 'domain-computers') in got # MAQ > 0
	assert ('ESC1', 'DCOnly', 'low-priv') not in got
	assert ('ESC4', 'PropWrite', 'low-priv') in got # schema GUID resolved
	assert ('ESC13', 'Linked', 'low-priv') in got
	assert ('ESC5', 'Certificate Templates', 'low-priv') in got # CreateChild on templates container
	assert all(f.enabled for f in findings if f.object_type == 'TEMPLATE')
	# configuration NC must come from the RootDSE
	assert all(tree is None or 'DC=corp,DC=local' in tree for _, tree in client.searches)
	assert any(tree == 'CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' for _, tree in client.searches)


class TestLabFindings:
	"""Cases found by comparing with certipy on GOAD (essos)"""
	def test_any_purpose_is_also_esc3(self):
		res = escs(template(ekus = (EKU_ANY_PURPOSE_OID,)))
		assert 'ESC2' in res and 'ESC3' in res

	def test_esc17_webserver(self):
		# GOAD WebServer: schema 1, enrollee supplies subject, server auth only
		res = escs(template(schema = 1, name_flag = 1, ekus = (EKU_SERVER_AUTHENTICATION_OID,)))
		assert res == {'ESC15', 'ESC17'}

	def test_disabled_templates_skipped_by_default(self):
		t = template(name_flag = 1)
		t.enroll_services = []
		assert analyze_templates([t], [PrincipalSet.lowpriv(D)]) == []
		assert {f.esc for f in analyze_templates([t], [PrincipalSet.lowpriv(D)], include_disabled = True)} == {'ESC1'}

	def test_esc3_target_needs_an_agent_template(self):
		user_tmpl = template(schema = 1) # like the default User template
		agent = template(ekus = (EKU_CERTIFICATE_REQUEST_AGENT_OID,))
		lp = [PrincipalSet.lowpriv(D)]
		assert 'ESC3-TARGET' not in {f.esc for f in analyze_templates([user_tmpl], lp)}
		assert 'ESC3-TARGET' in {f.esc for f in analyze_templates([user_tmpl, agent], lp)}

	def test_esc3_target_correlation_is_per_principal_set(self):
		user_tmpl = template(schema = 1)
		agent_dc_only = template('(OA;;CR;%s;;%s)' % (EX_RIGHT_CERTIFICATE_ENROLLMENT, DC), ekus = (EKU_CERTIFICATE_REQUEST_AGENT_OID,))
		res = {(f.esc, f.principal_set.label) for f in analyze_templates([user_tmpl, agent_dc_only], [PrincipalSet.lowpriv(D), PrincipalSet.domain_computers(D)])}
		assert ('ESC3-TARGET', 'low-priv') not in res
		assert ('ESC3-TARGET', 'domain-computers') in res


async def test_audit_adcs_foreign_user():
	"""A user from a trusted forest is not a member of this domain's Domain Users (certipy overstates this)"""
	client = _make_fake_client()
	client.whoami_res = 'u:NORTH\\hodor'
	got = set()
	async for finding, err in client.audit_adcs(include_lowpriv = False, include_domain_computers = False):
		assert err is None, err
		got.add((finding.esc, finding.object_name, finding.principal_set.label))
	# all templates in the fake domain are enrollable by Domain Users only
	assert not any(label == 'current-user-foreign' and esc == 'ESC1' for esc, _, label in got)


class TestDedupe:
	"""GOAD run: every finding was printed for both low-priv and domain-computers"""
	def test_broader_set_is_folded_into_narrower(self):
		lp, dc = PrincipalSet.lowpriv(D), PrincipalSet.domain_computers(D, 10)
		res = analyze_templates([template(name_flag = 1)], [lp, dc])
		assert [(f.esc, f.principal_set.label) for f in res] == [('ESC1', 'low-priv')]
		assert res[0].also_applies_to == ['domain-computers']

	def test_current_user_folded_when_superset(self):
		cu = PrincipalSet.current_user([USER, DU, 'S-1-5-32-545'])
		res = analyze_templates([template(name_flag = 1)], [cu, PrincipalSet.lowpriv(D)])
		assert [(f.esc, f.principal_set.label) for f in res] == [('ESC1', 'low-priv')]
		assert res[0].also_applies_to == ['current-user']

	def test_not_folded_when_not_superset(self):
		# foreign user: Everyone + Authenticated Users, template enrollable by Authenticated Users
		t = template('(OA;;CR;%s;;S-1-5-11)' % EX_RIGHT_CERTIFICATE_ENROLLMENT, name_flag = 1)
		foreign = PrincipalSet.current_user([], label = 'current-user-foreign')
		res = analyze_templates([t], [foreign, PrincipalSet.lowpriv(D)])
		# foreign set is narrower than low-priv, so it is the one kept
		assert [(f.esc, f.principal_set.label) for f in res] == [('ESC1', 'current-user-foreign')]
		assert res[0].also_applies_to == ['low-priv']

	def test_domain_computers_only_finding_kept(self):
		t = template('(OA;;CR;%s;;%s)' % (EX_RIGHT_CERTIFICATE_ENROLLMENT, DC), name_flag = 1)
		res = analyze_templates([t], [PrincipalSet.lowpriv(D), PrincipalSet.domain_computers(D, 10)])
		assert [(f.esc, f.principal_set.label) for f in res] == [('ESC1', 'domain-computers')]

	def test_pki_object_dedupe(self):
		s = sd('(A;;0xf01ff;;;%s)' % DU)
		res = analyze_pki_object('PKS', 'CN=PKS', s, [PrincipalSet.lowpriv(D), PrincipalSet.domain_computers(D)])
		assert len(res) == 1 and res[0].also_applies_to == ['domain-computers']
