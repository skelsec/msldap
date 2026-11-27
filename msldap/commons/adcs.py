"""
ADCS (Active Directory Certificate Services) misconfiguration analysis.

Everything in this module is offline: it works on already-fetched LDAP
objects (certificate templates, issuance policies, PKI container objects),
so it can be unit tested without a domain controller. The LDAP fetching
lives in `MSLDAPClient.audit_adcs`.

Findings are evaluated per *principal set*. A principal set is a labelled
group of SIDs that "we" can act as, for example:
  - the current user (tokenGroups + Everyone + Authenticated Users)
  - well-known low privileged groups (anyone in the domain)
  - Domain Computers when ms-DS-MachineAccountQuota > 0 (anyone can create one)
  - any other principal the caller controls (e.g. credentials it holds)

Covered (LDAP-visible) checks: ESC1, ESC2, ESC3 (agent + target template),
ESC4, ESC5 (PKI objects), ESC9, ESC13, ESC15.
Not covered here (needs CA registry/RPC): ESC6, ESC7, ESC8, ESC11, ESC16.
"""

import enum
from typing import Dict, Iterable, List, Optional, Set

from winacl.dtyp.ace import ACEType, AceFlags, ACE_OBJECT_PRESENCE
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

EX_RIGHT_CERTIFICATE_ENROLLMENT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
EX_RIGHT_CERTIFICATE_AUTOENROLLMENT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# raw access mask bits, winacl versions before the GENERIC_WRITE fix had 0x4000000 there
_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000
_ADS_GENERIC_ALL = 0x000F01FF
_ADS_GENERIC_WRITE = 0x00020028
_CREATE_CHILD = 0x00000001
_WRITE_PROP = 0x00000020
_CONTROL_ACCESS = 0x00000100
_WRITE_DACL = 0x00040000
_WRITE_OWNER = 0x00080000

_ALLOW_TYPES = (ACEType.ACCESS_ALLOWED_ACE_TYPE, ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE)
_DENY_TYPES = (ACEType.ACCESS_DENIED_ACE_TYPE, ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE)

SID_EVERYONE = 'S-1-1-0'
SID_AUTHENTICATED_USERS = 'S-1-5-11'
SID_BUILTIN_USERS = 'S-1-5-32-545'
RID_DOMAIN_USERS = '513'
RID_DOMAIN_COMPUTERS = '515'

# Attributes that make a template exploitable when they can be written (ESC4).
# Their schemaIDGUIDs are resolved at runtime from the schema.
ESC4_DANGEROUS_ATTRIBUTES = [
	'msPKI-Certificate-Name-Flag',
	'msPKI-Enrollment-Flag',
	'msPKI-RA-Signature',
	'msPKI-RA-Application-Policies',
	'msPKI-Certificate-Application-Policy',
	'msPKI-Certificate-Policy',
	'msPKI-Template-Schema-Version',
	'msPKI-Private-Key-Flag',
	'pKIExtendedKeyUsage',
]

def wellknown_lowpriv_sids(domain_sid:str) -> Set[str]:
	"""SIDs every authenticated domain user is effectively a member of"""
	sids = {SID_EVERYONE, SID_AUTHENTICATED_USERS, SID_BUILTIN_USERS}
	if domain_sid is not None:
		sids.add('%s-%s' % (domain_sid, RID_DOMAIN_USERS))
	return sids

def domain_computers_sid(domain_sid:str) -> str:
	return '%s-%s' % (domain_sid, RID_DOMAIN_COMPUTERS)


class PrincipalSet:
	"""A labelled set of SIDs that the caller can act as"""
	def __init__(self, label:str, sids:Iterable[str], description:str = None):
		self.label = label
		self.sids = set(str(sid).upper() for sid in sids)
		self.description = description

	@staticmethod
	def current_user(tokengroups:Iterable[str], label:str = 'current-user', description:str = None):
		"""tokenGroups does not include Everyone/Authenticated Users, those are added by LSA at logon"""
		sids = set(str(x) for x in tokengroups)
		sids.update([SID_EVERYONE, SID_AUTHENTICATED_USERS])
		return PrincipalSet(label, sids, description = description or 'Current user token groups')

	@staticmethod
	def lowpriv(domain_sid:str):
		return PrincipalSet('low-priv', wellknown_lowpriv_sids(domain_sid), description = 'Any authenticated domain user')

	@staticmethod
	def domain_computers(domain_sid:str, maq:int = None):
		desc = 'Domain Computers'
		if maq is not None:
			desc += ' (ms-DS-MachineAccountQuota=%s, any user can create a machine account)' % maq
		sids = wellknown_lowpriv_sids(domain_sid)
		sids.add(domain_computers_sid(domain_sid))
		return PrincipalSet('domain-computers', sids, description = desc)

	def to_dict(self):
		return {
			'label' : self.label,
			'description' : self.description,
			'sids' : sorted(self.sids),
		}


class EffectiveRights:
	"""Rights a principal set holds over one object, with the SIDs that grant them"""
	def __init__(self):
		self.is_owner = False
		self.full_control:Set[str] = set()
		self.write_dacl:Set[str] = set()
		self.write_owner:Set[str] = set()
		self.write_all_properties:Set[str] = set()
		self.write_property:Dict[str, Set[str]] = {} # attribute guid -> sids
		self.all_extended_rights:Set[str] = set()
		self.enroll:Set[str] = set()
		self.autoenroll:Set[str] = set()
		self.create_child:Set[str] = set()
		self.owner_sid = None

	@property
	def enroll_granting_sids(self) -> Set[str]:
		"""Enroll is granted by the Enroll extended right, All-Extended-Rights or GenericAll"""
		return self.enroll | self.all_extended_rights | self.full_control

	@property
	def can_enroll(self) -> bool:
		return len(self.enroll_granting_sids) > 0

	def dangerous_permissions(self, dangerous_guids:Dict[str, str] = None) -> List[str]:
		"""Returns human readable list of object-control permissions.
		dangerous_guids: attribute guid -> attribute name. When None, every
		attribute-specific write is reported (unresolved guid)."""
		issues = []
		if self.is_owner:
			issues.append('Owner (%s)' % self.owner_sid)
		if self.full_control:
			issues.append('GenericAll (%s)' % ', '.join(sorted(self.full_control)))
		if self.write_dacl:
			issues.append('WriteDacl (%s)' % ', '.join(sorted(self.write_dacl)))
		if self.write_owner:
			issues.append('WriteOwner (%s)' % ', '.join(sorted(self.write_owner)))
		if self.write_all_properties:
			issues.append('WriteProperty all attributes (%s)' % ', '.join(sorted(self.write_all_properties)))
		for guid, sids in self.write_property.items():
			if dangerous_guids is None:
				issues.append('WriteProperty on unresolved attribute %s (%s)' % (guid, ', '.join(sorted(sids))))
			elif guid in dangerous_guids:
				issues.append('WriteProperty %s (%s)' % (dangerous_guids[guid], ', '.join(sorted(sids))))
		return issues


class ACLModel:
	"""Normalized view of an object's DACL that can be evaluated for any set of SIDs.

	Evaluation: a right is held if at least one matching allow ACE grants it
	and no matching deny ACE removes it (ACE order is not considered, AD
	stores DACLs in canonical order). Inherit-only ACEs are ignored as they
	do not apply to the object itself. Limitation: a deny on one specific
	attribute does not reduce a "write all properties" grant."""
	def __init__(self, sd:SECURITY_DESCRIPTOR):
		self.sd = sd
		self.owner = str(sd.Owner).upper() if sd is not None and sd.Owner is not None else None
		self.entries = [] # (is_allow, sid, mask, object_type)
		if sd is None or sd.Dacl is None:
			return
		for ace in sd.Dacl.aces:
			if ace.AceType in _ALLOW_TYPES:
				is_allow = True
			elif ace.AceType in _DENY_TYPES:
				is_allow = False
			else:
				continue
			if int(ace.AceFlags or 0) & int(AceFlags.INHERIT_ONLY_ACE):
				continue
			mask = int(ace.Mask)
			if mask & _GENERIC_ALL:
				mask |= _ADS_GENERIC_ALL
			if mask & _GENERIC_WRITE:
				mask |= _ADS_GENERIC_WRITE
			object_type = None
			if ace.AceType in (ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE):
				if ace.Flags is not None and int(ace.Flags) & int(ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT) and ace.ObjectType is not None:
					object_type = str(ace.ObjectType).lower()
			self.entries.append((is_allow, str(ace.Sid).upper(), mask, object_type))

	@staticmethod
	def _apply(rights:EffectiveRights, sid:str, mask:int, object_type:Optional[str], add:bool):
		def upd(s:Set[str]):
			if add:
				s.add(sid)
			else:
				s.clear()

		# GenericAll (0xF01FF) contains every bit below, so its components are
		# filled in individually as well. Any matching deny breaks "full control".
		if add is False:
			rights.full_control.clear()
		elif object_type is None and (mask & _ADS_GENERIC_ALL) == _ADS_GENERIC_ALL:
			rights.full_control.add(sid)
		if mask & _WRITE_DACL:
			upd(rights.write_dacl)
		if mask & _WRITE_OWNER:
			upd(rights.write_owner)
		if mask & _CREATE_CHILD and object_type is None:
			upd(rights.create_child)
		if mask & _WRITE_PROP:
			if object_type is None:
				upd(rights.write_all_properties)
				if not add:
					rights.write_property.clear()
			else:
				if add:
					rights.write_property.setdefault(object_type, set()).add(sid)
				else:
					rights.write_property.pop(object_type, None)
		if mask & _CONTROL_ACCESS:
			if object_type is None:
				upd(rights.all_extended_rights)
				if not add:
					rights.enroll.clear()
					rights.autoenroll.clear()
			elif object_type == EX_RIGHT_CERTIFICATE_ENROLLMENT:
				upd(rights.enroll)
			elif object_type == EX_RIGHT_CERTIFICATE_AUTOENROLLMENT:
				upd(rights.autoenroll)

	def evaluate(self, sids:Iterable[str]) -> EffectiveRights:
		sids = set(str(x).upper() for x in sids)
		rights = EffectiveRights()
		rights.owner_sid = self.owner
		rights.is_owner = self.owner is not None and self.owner in sids
		for is_allow, sid, mask, object_type in self.entries:
			if is_allow and sid in sids:
				ACLModel._apply(rights, sid, mask, object_type, True)
		for is_allow, sid, mask, object_type in self.entries:
			if not is_allow and sid in sids:
				ACLModel._apply(rights, sid, mask, object_type, False)
		return rights

	def allowed_sids(self) -> Dict[str, Set[str]]:
		"""Legacy view: SIDs per right from allow ACEs only (no deny evaluation)"""
		res = {
			'enroll' : set(),
			'autoenroll' : set(),
			'allextendedrights' : set(),
			'fullcontrol' : set(),
			'write_dacl' : set(),
			'write_owner' : set(),
			'write_property' : set(),
		}
		for is_allow, sid, mask, object_type in self.entries:
			if not is_allow:
				continue
			r = EffectiveRights()
			ACLModel._apply(r, sid, mask, object_type, True)
			if r.enroll:
				res['enroll'].add(sid)
			if r.autoenroll:
				res['autoenroll'].add(sid)
			if r.all_extended_rights:
				res['allextendedrights'].add(sid)
			if r.full_control:
				res['fullcontrol'].add(sid)
			if r.write_dacl:
				res['write_dacl'].add(sid)
			if r.write_owner:
				res['write_owner'].add(sid)
			if r.write_all_properties or r.write_property:
				res['write_property'].add(sid)
		return res


class ADCSFindingSeverity(enum.Enum):
	CRITICAL = 'CRITICAL'
	HIGH = 'HIGH'
	MEDIUM = 'MEDIUM'
	INFO = 'INFO'


class ADCSFinding:
	def __init__(self, esc:str, object_type:str, object_name:str, object_dn:str,
			principal_set:PrincipalSet, reason:str, granting_sids:Iterable[str] = None,
			severity:ADCSFindingSeverity = ADCSFindingSeverity.HIGH, enabled:bool = None,
			enrollment_services:List[str] = None, prerequisites:List[str] = None):
		self.esc = esc
		self.object_type = object_type # 'TEMPLATE' / 'PKIOBJECT'
		self.object_name = object_name
		self.object_dn = object_dn
		self.principal_set = principal_set
		self.reason = reason
		self.granting_sids = sorted(set(granting_sids or []))
		self.severity = severity
		self.enabled = enabled
		self.enrollment_services = enrollment_services or []
		self.prerequisites = prerequisites or []
		self.also_applies_to:List[str] = [] # labels of broader principal sets with the same finding

	def to_dict(self):
		return {
			'esc' : self.esc,
			'object_type' : self.object_type,
			'object_name' : self.object_name,
			'object_dn' : self.object_dn,
			'principal_set' : self.principal_set.label if self.principal_set is not None else None,
			'principal_set_description' : self.principal_set.description if self.principal_set is not None else None,
			'reason' : self.reason,
			'granting_sids' : self.granting_sids,
			'severity' : self.severity.value,
			'enabled' : self.enabled,
			'enrollment_services' : self.enrollment_services,
			'prerequisites' : self.prerequisites,
			'also_applies_to' : self.also_applies_to,
		}

	def __str__(self):
		t = '[%s] %s %s (as %s)\n' % (self.severity.value, self.esc, self.object_name, self.principal_set.label if self.principal_set else '?')
		t += '  Reason: %s\n' % self.reason
		if self.enabled is not None:
			t += '  Enabled: %s\n' % self.enabled
		if self.enrollment_services:
			t += '  Enrollment services: %s\n' % ', '.join(self.enrollment_services)
		if self.granting_sids:
			t += '  Granted via: %s\n' % ', '.join(self.granting_sids)
		if self.also_applies_to:
			t += '  Also applies to: %s\n' % ', '.join(self.also_applies_to)
		for p in self.prerequisites:
			t += '  Prerequisite: %s\n' % p
		return t


def _template_blockers(template) -> List[str]:
	"""Conditions that stop a regular (non-agent) enrollment from being exploitable"""
	blockers = []
	if template.requires_manager_approval():
		blockers.append('manager approval required')
	if template.requires_authorized_signatures():
		blockers.append('%s authorized signature(s) required' % template.RA_Signature)
	return blockers

def analyze_template(template, principal_sets:List[PrincipalSet],
		linked_issuance_policies:Dict[str, str] = None,
		dangerous_guids:Dict[str, str] = None) -> List[ADCSFinding]:
	"""Evaluates one MSADCertificateTemplate for every principal set.

	:param linked_issuance_policies: issuance policy OID -> linked group DN (msDS-OIDToGroupLink), used for ESC13
	:param dangerous_guids: attribute schemaIDGUID -> attribute name, used for ESC4. None = report any attribute write
	"""
	findings = []
	acl = template.acl
	enabled = template.is_enabled
	services = list(template.enroll_services)
	blockers = _template_blockers(template)

	for pset in principal_sets:
		rights = acl.evaluate(pset.sids)

		def add(esc, reason, granting, severity = ADCSFindingSeverity.HIGH, prerequisites = None):
			findings.append(ADCSFinding(
				esc, 'TEMPLATE', template.name, template.distinguishedName, pset, reason,
				granting_sids = granting, severity = severity, enabled = enabled,
				enrollment_services = services, prerequisites = prerequisites,
			))

		# ESC4 is about controlling the template object, independent of enrollment
		perm_issues = rights.dangerous_permissions(dangerous_guids)
		if perm_issues:
			granting = set()
			granting.update(rights.full_control, rights.write_dacl, rights.write_owner, rights.write_all_properties)
			for guid, sids in rights.write_property.items():
				if dangerous_guids is None or guid in dangerous_guids:
					granting.update(sids)
			if rights.is_owner:
				granting.add(rights.owner_sid)
			add('ESC4', 'Template can be modified: %s' % '; '.join(perm_issues), granting, ADCSFindingSeverity.CRITICAL)

		if not rights.can_enroll:
			continue
		enroll_sids = rights.enroll_granting_sids

		if not blockers:
			if template.allows_authentication() and template.allows_to_specify_san():
				add('ESC1', 'Enrollee supplies subject and template allows client authentication', enroll_sids, ADCSFindingSeverity.CRITICAL)

			if template.can_be_used_for_any_purpose():
				what = 'no EKU (SubCA-like)' if len(template.pKIExtendedKeyUsage or []) == 0 else 'Any Purpose EKU'
				add('ESC2', 'Template has %s, certificate usable for client auth and as enrollment agent' % what, enroll_sids)

			if template.allows_to_use_agent_certificate():
				what = 'Certificate Request Agent EKU' if template.allows_to_request_agent_certificate() else 'Any Purpose EKU'
				add('ESC3', 'Template issues enrollment agent certificates (%s)' % what, enroll_sids,
					prerequisites = ['A template enrollable on behalf of others (ESC3-TARGET) and no CA enrollment agent restrictions'])

			if template.no_security_extension() and template.allows_authentication():
				add('ESC9', 'Template has CT_FLAG_NO_SECURITY_EXTENSION and allows client authentication', enroll_sids,
					prerequisites = [
						'GenericWrite over an account to change its UPN',
						'StrongCertificateBindingEnforcement != 2 on DCs (or CertificateMappingMethods contains UPN for Schannel)',
					])

			if linked_issuance_policies and template.allows_authentication():
				linked = [(oid, linked_issuance_policies[oid]) for oid in template.Certificate_Policy if oid in linked_issuance_policies]
				if linked:
					add('ESC13', 'Template issuance policy is linked to group(s): %s' % ', '.join('%s -> %s' % x for x in linked), enroll_sids)

			if template.allows_to_specify_san() and template.allows_server_authentication():
				add('ESC17', 'Enrollee supplies subject and template allows server authentication (server impersonation / MitM)', enroll_sids,
					severity = ADCSFindingSeverity.MEDIUM,
					prerequisites = ['A position to intercept or redirect traffic to the impersonated service'])

			if template.schema_version == 1 and template.allows_to_specify_san():
				add('ESC15', 'Schema version 1 template with enrollee supplied subject (application policy injection, CVE-2024-49019)', enroll_sids,
					prerequisites = ['CA not patched for CVE-2024-49019 (November 2024)'])

		if template.is_enrollment_agent_target() and template.allows_authentication() and not template.requires_manager_approval():
			add('ESC3-TARGET', 'Template allows enrollment on behalf of other principals using an enrollment agent certificate', enroll_sids,
				severity = ADCSFindingSeverity.MEDIUM,
				prerequisites = ['An enrollment agent certificate (see ESC3)'])

	return findings


def dedupe_findings(findings:List[ADCSFinding], principal_sets:List[PrincipalSet]) -> List[ADCSFinding]:
	"""Drops a finding of principal set B when the same finding (ESC + object) was already
	reported for a set A whose SIDs are a subset of B's: B can do anything A can, so the
	B finding adds nothing. The dropped set is recorded in the kept finding's also_applies_to."""
	order = {pset.label: i for i, pset in enumerate(principal_sets)}
	# narrower sets first so they are the ones kept
	narrow_first = sorted(principal_sets, key = lambda x: (len(x.sids), order[x.label]))
	rank = {pset.label: i for i, pset in enumerate(narrow_first)}
	by_label = {pset.label: pset for pset in principal_sets}
	kept = {} # (esc, dn) -> list of kept findings
	result = []
	for f in sorted(findings, key = lambda x: rank.get(x.principal_set.label, len(rank))):
		key = (f.esc, f.object_dn)
		covering = None
		for k in kept.get(key, []):
			if by_label[k.principal_set.label].sids <= by_label[f.principal_set.label].sids:
				covering = k
				break
		if covering is not None:
			covering.also_applies_to.append(f.principal_set.label)
			continue
		kept.setdefault(key, []).append(f)
		result.append(f)
	# keep the original (template) order for output
	position = {id(f): i for i, f in enumerate(findings)}
	return sorted(result, key = lambda x: position[id(x)])


def analyze_templates(templates, principal_sets:List[PrincipalSet],
		linked_issuance_policies:Dict[str, str] = None,
		dangerous_guids:Dict[str, str] = None, include_disabled:bool = False) -> List[ADCSFinding]:
	"""Evaluates a set of templates together. Compared to calling analyze_template one by one:
	  - templates not published on any CA are skipped unless include_disabled is True
	  - ESC3-TARGET is only kept for a principal set that can also obtain an
	    enrollment agent certificate (ESC3), otherwise the default User/Machine
	    templates would be reported in every domain"""
	findings = []
	for template in templates:
		if include_disabled is False and template.is_enabled is False:
			continue
		findings.extend(analyze_template(template, principal_sets, linked_issuance_policies = linked_issuance_policies, dangerous_guids = dangerous_guids))
	has_agent = set(f.principal_set.label for f in findings if f.esc == 'ESC3' and f.enabled is not False)
	findings = [f for f in findings if f.esc != 'ESC3-TARGET' or f.principal_set.label in has_agent]
	return dedupe_findings(findings, principal_sets)


def analyze_pki_object(name:str, dn:str, sd:SECURITY_DESCRIPTOR, principal_sets:List[PrincipalSet], allow_create_child:bool = False) -> List[ADCSFinding]:
	"""ESC5: control over PKI infrastructure objects (containers, enrollment services, NTAuthCertificates, ...)

	:param allow_create_child: when True, CreateChild is also dangerous (e.g. Certificate Templates container)
	"""
	findings = []
	acl = ACLModel(sd)
	for pset in principal_sets:
		rights = acl.evaluate(pset.sids)
		issues = rights.dangerous_permissions(dangerous_guids = {}) # attribute specific writes are not relevant here
		granting = set()
		granting.update(rights.full_control, rights.write_dacl, rights.write_owner, rights.write_all_properties)
		if rights.is_owner:
			granting.add(rights.owner_sid)
		if allow_create_child and rights.create_child:
			issues.append('CreateChild (%s)' % ', '.join(sorted(rights.create_child)))
			granting.update(rights.create_child)
		if issues:
			findings.append(ADCSFinding(
				'ESC5', 'PKIOBJECT', name, dn, pset,
				'PKI object can be modified: %s' % '; '.join(issues),
				granting_sids = granting, severity = ADCSFindingSeverity.CRITICAL,
			))
	return dedupe_findings(findings, principal_sets)
