import os
import zipfile
import json
import base64
import datetime
import asyncio

from tqdm import tqdm

from msldap.external.bloodhoundpy.acls import parse_binary_acl
from msldap.external.bloodhoundpy.resolver import resolve_aces, WELLKNOWN_SIDS
from msldap.external.bloodhoundpy.utils import parse_gplink_string, is_filtered_container, is_filtered_container_child, reverse_dn_components, explode_dn
from msldap.commons.factory import LDAPConnectionFactory
from msldap.connection import MSLDAPClientConnection
from msldap.client import MSLDAPClient
from msldap.commons.adexplorer import Snapshot
from msldap import logger

async def dummy_print(msg):
	print(msg)

class MSLDAPDump2Bloodhound:
	def __init__(self, url: str or MSLDAPClient or LDAPConnectionFactory or MSLDAPClientConnection, progress = True, output_path = None, use_mp:bool=True, print_cb = None, follow_trusts:bool=False):
		self.debug = False
		self.ldap_url = url
		self.connection: MSLDAPClient = None
		self.ldapinfo = None
		self.domainname = None
		self.domainsid = None
		self.use_mp = use_mp
		self.mp_sdbatch_length = 5000
		self.print_cb = print_cb
		self.with_progress = progress
		self.follow_trusts = follow_trusts
		if self.print_cb is None:
			self.print_cb = dummy_print

		self.DNs = {}
		self.DNs_sorted = {}
		self.ocache = {}
		self.schema = cn_to_schemaid = {
			"account": "2628a46a-a6ad-4ae0-b854-2b12d9fe6f9e",
			"acs-policy": "7f561288-5301-11d1-a9c5-0000f80367c1",
			"acs-resource-limits": "2e899b04-2834-11d3-91d4-0000f87a57d4",
			"acs-subnet": "7f561289-5301-11d1-a9c5-0000f80367c1",
			"address-book-container": "3e74f60f-3e73-11d1-a9c0-0000f80367c1",
			"address-template": "5fd4250a-1262-11d0-a060-00aa006c33ed",
			"application-entity": "3fdfee4f-47f4-11d1-a9c3-0000f80367c1",
			"application-process": "5fd4250b-1262-11d0-a060-00aa006c33ed",
			"application-settings": "f780acc1-56f0-11d1-a9c6-0000f80367c1",
			"application-site-settings": "19195a5c-6da0-11d0-afd3-00c04fd930c9",
			"application-version": "ddc790ac-af4d-442a-8f0f-a1d4caa7dd92",
			"attribute-schema": "bf967a80-0de6-11d0-a285-00aa003049e2",
			"bootabledevice": "4bcb2477-4bb3-4545-a9fc-fb66e136b435",
			"builtin-domain": "bf967a81-0de6-11d0-a285-00aa003049e2",
			"category-registration": "7d6c0e9d-7e20-11d0-afd6-00c04fd930c9",
			"certification-authority": "3fdfee50-47f4-11d1-a9c3-0000f80367c1",
			"class-registration": "bf967a82-0de6-11d0-a285-00aa003049e2",
			"class-schema": "bf967a83-0de6-11d0-a285-00aa003049e2",
			"class-store": "bf967a84-0de6-11d0-a285-00aa003049e2",
			"com-connection-point": "bf967a85-0de6-11d0-a285-00aa003049e2",
			"computer": "bf967a86-0de6-11d0-a285-00aa003049e2",
			"configuration": "bf967a87-0de6-11d0-a285-00aa003049e2",
			"connection-point": "5cb41ecf-0e4c-11d0-a286-00aa003049e2",
			"contact": "5cb41ed0-0e4c-11d0-a286-00aa003049e2",
			"container": "bf967a8b-0de6-11d0-a285-00aa003049e2",
			"control-access-right": "8297931e-86d3-11d0-afda-00c04fd930c9",
			"country": "bf967a8c-0de6-11d0-a285-00aa003049e2",
			"crl-distribution-point": "167758ca-47f3-11d1-a9c3-0000f80367c1",
			"cross-ref": "bf967a8d-0de6-11d0-a285-00aa003049e2",
			"cross-ref-container": "ef9e60e0-56f7-11d1-a9c6-0000f80367c1",
			"device": "bf967a8e-0de6-11d0-a285-00aa003049e2",
			"dfs-configuration": "8447f9f2-1027-11d0-a05f-00aa006c33ed",
			"dhcp-class": "963d2756-48be-11d1-a9c3-0000f80367c1",
			"display-specifier": "e0fa1e8a-9b45-11d0-afdd-00c04fd930c9",
			"display-template": "5fd4250c-1262-11d0-a060-00aa006c33ed",
			"dmd": "bf967a8f-0de6-11d0-a285-00aa003049e2",
			"dns-node": "e0fa1e8c-9b45-11d0-afdd-00c04fd930c9",
			"dns-zone": "e0fa1e8b-9b45-11d0-afdd-00c04fd930c9",
			"dns-zone-scope": "696f8a61-2d3f-40ce-a4b3-e275dfcc49c5",
			"dns-zone-scope-container": "f2699093-f25a-4220-9deb-03df4cc4a9c5",
			"document": "39bad96d-c2d6-4baf-88ab-7e4207600117",
			"documentseries": "7a2be07c-302f-4b96-bc90-0795d66885f8",
			"domain": "19195a5a-6da0-11d0-afd3-00c04fd930c9",
			"domain-dns": "19195a5b-6da0-11d0-afd3-00c04fd930c9",
			"domain-policy": "bf967a99-0de6-11d0-a285-00aa003049e2",
			"domainrelatedobject": "8bfd2d3d-efda-4549-852c-f85e137aedc6",
			"dsa": "3fdfee52-47f4-11d1-a9c3-0000f80367c1",
			"ds-ui-settings": "09b10f14-6f93-11d2-9905-0000f87a57d4",
			"dynamic-object": "66d51249-3355-4c1f-b24e-81f252aca23b",
			"file-link-tracking": "dd712229-10e4-11d0-a05f-00aa006c33ed",
			"file-link-tracking-entry": "8e4eb2ed-4712-11d0-a1a0-00c04fd930c9",
			"foreign-security-principal": "89e31c12-8530-11d0-afda-00c04fd930c9",
			"friendlycountry": "c498f152-dc6b-474a-9f52-7cdba3d7d351",
			"ft-dfs": "8447f9f3-1027-11d0-a05f-00aa006c33ed",
			"group": "bf967a9c-0de6-11d0-a285-00aa003049e2",
			"group-of-names": "bf967a9d-0de6-11d0-a285-00aa003049e2",
			"groupofuniquenames": "0310a911-93a3-4e21-a7a3-55d85ab2c48b",
			"group-policy-container": "f30e3bc2-9ff0-11d1-b603-0000f80367c1",
			"ieee802device": "a699e529-a637-4b7d-a0fb-5dc466a0b8a7",
			"index-server-catalog": "7bfdcb8a-4807-11d1-a9c3-0000f80367c1",
			"inetorgperson": "4828cc14-1437-45bc-9b07-ad6f015e5f28",
			"infrastructure-update": "2df90d89-009f-11d2-aa4c-00c04fd7d83a",
			"intellimirror-group": "07383086-91df-11d1-aebc-0000f80367c1",
			"intellimirror-scp": "07383085-91df-11d1-aebc-0000f80367c1",
			"inter-site-transport": "26d97376-6070-11d1-a9c6-0000f80367c1",
			"inter-site-transport-container": "26d97375-6070-11d1-a9c6-0000f80367c1",
			"iphost": "ab911646-8827-4f95-8780-5a8f008eb68f",
			"ipnetwork": "d95836c3-143e-43fb-992a-b057f1ecadf9",
			"ipprotocol": "9c2dcbd2-fbf0-4dc7-ace0-8356dcd0f013",
			"ipsec-base": "b40ff825-427a-11d1-a9c2-0000f80367c1",
			"ipsec-filter": "b40ff826-427a-11d1-a9c2-0000f80367c1",
			"ipsec-isakmp-policy": "b40ff828-427a-11d1-a9c2-0000f80367c1",
			"ipsec-negotiation-policy": "b40ff827-427a-11d1-a9c2-0000f80367c1",
			"ipsec-nfa": "b40ff829-427a-11d1-a9c2-0000f80367c1",
			"ipsec-policy": "b7b13121-b82e-11d0-afee-0000f80367c1",
			"ipservice": "2517fadf-fa97-48ad-9de6-79ac5721f864",
			"leaf": "bf967a9e-0de6-11d0-a285-00aa003049e2",
			"licensing-site-settings": "1be8f17d-a9ff-11d0-afe2-00c04fd930c9",
			"link-track-object-move-table": "ddac0cf5-af8f-11d0-afeb-00c04fd930c9",
			"link-track-omt-entry": "ddac0cf7-af8f-11d0-afeb-00c04fd930c9",
			"link-track-vol-entry": "ddac0cf6-af8f-11d0-afeb-00c04fd930c9",
			"link-track-volume-table": "ddac0cf4-af8f-11d0-afeb-00c04fd930c9",
			"locality": "bf967aa0-0de6-11d0-a285-00aa003049e2",
			"lost-and-found": "52ab8671-5709-11d1-a9c6-0000f80367c1",
			"mail-recipient": "bf967aa1-0de6-11d0-a285-00aa003049e2",
			"meeting": "11b6cc94-48c4-11d1-a9c3-0000f80367c1",
			"ms-net-ieee-80211-grouppolicy": "1cb81863-b822-4379-9ea2-5ff7bdc6386d",
			"ms-net-ieee-8023-grouppolicy": "99a03a6a-ab19-4446-9350-0cb878ed2d9b",
			"ms-sql-olapcube": "09f0506a-cd28-11d2-9993-0000f87a57d4",
			"ms-sql-olapdatabase": "20af031a-ccef-11d2-9993-0000f87a57d4",
			"ms-sql-olapserver": "0c7e18ea-ccef-11d2-9993-0000f87a57d4",
			"ms-sql-sqldatabase": "1d08694a-ccef-11d2-9993-0000f87a57d4",
			"ms-sql-sqlpublication": "17c2f64e-ccef-11d2-9993-0000f87a57d4",
			"ms-sql-sqlrepository": "11d43c5c-ccef-11d2-9993-0000f87a57d4",
			"ms-sql-sqlserver": "05f6c878-ccef-11d2-9993-0000f87a57d4",
			"ms-authz-central-access-policies": "555c21c3-a136-455a-9397-796bbd358e25",
			"ms-authz-central-access-policy": "a5679cb0-6f9d-432c-8b75-1e3e834f02aa",
			"ms-authz-central-access-rule": "5b4a06dc-251c-4edb-8813-0bdd71327226",
			"ms-authz-central-access-rules": "99bb1b7a-606d-4f8b-800e-e15be554ca8d",
			"ms-com-partition": "c9010e74-4e58-49f7-8a89-5e3e2340fcf8",
			"ms-com-partitionset": "250464ab-c417-497a-975a-9e0d459a7ca1",
			"ms-dfs-deleted-link-v2": "25173408-04ca-40e8-865e-3f9ce9bf1bd3",
			"ms-dfs-link-v2": "7769fb7a-1159-4e96-9ccd-68bc487073eb",
			"ms-dfs-namespace-anchor": "da73a085-6e64-4d61-b064-015d04164795",
			"ms-dfs-namespace-v2": "21cb8628-f3c3-4bbf-bff6-060b2d8f299a",
			"ms-dfsr-connection": "e58f972e-64b5-46ef-8d8b-bbc3e1897eab",
			"ms-dfsr-content": "64759b35-d3a1-42e4-b5f1-a3de162109b3",
			"ms-dfsr-contentset": "4937f40d-a6dc-4d48-97ca-06e5fbfd3f16",
			"ms-dfsr-globalsettings": "7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6",
			"ms-dfsr-localsettings": "fa85c591-197f-477e-83bd-ea5a43df2239",
			"ms-dfsr-member": "4229c897-c211-437c-a5ae-dbf705b696e5",
			"ms-dfsr-replicationgroup": "1c332fe0-0c2a-4f32-afca-23c5e45a9e77",
			"ms-dfsr-subscriber": "e11505d7-92c4-43e7-bf5c-295832ffc896",
			"ms-dfsr-subscription": "67212414-7bcc-4609-87e0-088dad8abdee",
			"ms-dfsr-topology": "04828aa9-6e42-4e80-b962-e2fe00754d17",
			"ms-dns-server-settings": "ef2fc3ed-6e18-415b-99e4-3114a8cb124b",
			"ms-ds-app-configuration": "90df3c3e-1854-4455-a5d7-cad40d56657a",
			"ms-ds-app-data": "9e67d761-e327-4d55-bc95-682f875e2f8e",
			"ms-ds-authn-policies": "3a9adf5d-7b97-4f7e-abb4-e5b55c1c06b4",
			"ms-ds-authn-policy": "ab6a1156-4dc7-40f5-9180-8e4ce42fe5cd",
			"ms-ds-authn-policy-silo": "f9f0461e-697d-4689-9299-37e61d617b0d",
			"ms-ds-authn-policy-silos": "d2b1470a-8f84-491e-a752-b401ee00fe5c",
			"ms-ds-az-admin-manager": "cfee1051-5f28-4bae-a863-5d0cc18a8ed1",
			"ms-ds-az-application": "ddf8de9b-cba5-4e12-842e-28d8b66f75ec",
			"ms-ds-az-operation": "860abe37-9a9b-4fa4-b3d2-b8ace5df9ec5",
			"ms-ds-az-role": "8213eac9-9d55-44dc-925c-e9a52b927644",
			"ms-ds-az-scope": "4feae054-ce55-47bb-860e-5b12063a51de",
			"ms-ds-az-task": "1ed3a473-9b1b-418a-bfa0-3a37b95a5306",
			"ms-ds-claims-transformation-policies": "c8fca9b1-7d88-bb4f-827a-448927710762",
			"ms-ds-claims-transformation-policy-type": "2eeb62b3-1373-fe45-8101-387f1676edc7",
			"ms-ds-claim-type": "81a3857c-5469-4d8f-aae6-c27699762604",
			"ms-ds-claim-type-property-base": "b8442f58-c490-4487-8a9d-d80b883271ad",
			"ms-ds-claim-types": "36093235-c715-4821-ab6a-b56fb2805a58",
			"ms-ds-cloud-extensions": "641e87a4-8326-4771-ba2d-c706df35e35a",
			"ms-ds-delegated-managed-service-account": "0feb936f-47b3-49f2-9386-1dedc2c23765",
			"ms-ds-device": "5df2b673-6d41-4774-b3e8-d52e8ee9ff99",
			"ms-ds-device-container": "7c9e8c58-901b-4ea8-b6ec-4eb9e9fc0e11",
			"ms-ds-device-registration-service": "96bc3a1a-e3d2-49d3-af11-7b0df79d67f5",
			"ms-ds-device-registration-service-container": "310b55ce-3dcd-4392-a96d-c9e35397c24f",
			"ms-ds-group-managed-service-account": "7b8b558a-93a5-4af7-adca-c017e67f1057",
			"ms-ds-key-credential": "ee1f5543-7c2e-476a-8b3f-e11f4af6c498",
			"ms-ds-managed-service-account": "ce206244-5827-4a86-ba1c-1c0c386c1b64",
			"ms-ds-optional-feature": "44f00041-35af-468b-b20a-6ce8737c580b",
			"ms-ds-password-settings": "3bcd9db8-f84b-451c-952f-6c52b81f9ec6",
			"ms-ds-password-settings-container": "5b06b06a-4cf3-44c0-bd16-43bc10a987da",
			"ms-ds-quota-container": "da83fc4f-076f-4aea-b4dc-8f4dab9b5993",
			"ms-ds-quota-control": "de91fc26-bd02-4b52-ae26-795999e96fc7",
			"ms-ds-resource-properties": "7a4a4584-b350-478f-acd6-b4b852d82cc0",
			"ms-ds-resource-property": "5b283d5e-8404-4195-9339-8450188c501a",
			"ms-ds-resource-property-list": "72e3d47a-b342-4d45-8f56-baff803cabf9",
			"ms-ds-shadow-principal": "770f4cb3-1643-469c-b766-edd77aa75e14",
			"ms-ds-shadow-principal-container": "11f95545-d712-4c50-b847-d2781537c633",
			"ms-ds-value-type": "e3c27fdf-b01d-4f4e-87e7-056eef0eb922",
			"ms-exch-configuration-container": "d03d6858-06f4-11d2-aa53-00c04fd7d83a",
			"ms-fve-recoveryinformation": "ea715d30-8f53-40d0-bd1e-6109186d782c",
			"ms-ieee-80211-policy": "7b9a2d92-b7eb-4382-9772-c3e0f9baaf94",
			"ms-imaging-postscanprocess": "1f7c257c-b8a3-4525-82f8-11ccc7bee36e",
			"ms-imaging-psps": "a0ed2ac1-970c-4777-848e-ec63a0ec44fc",
			"ms-kds-prov-rootkey": "aa02fd41-17e0-4f18-8687-b2239649736b",
			"ms-kds-prov-serverconfiguration": "5ef243a8-2a25-45a6-8b73-08a71ae677ce",
			"msmq-custom-recipient": "876d6817-35cc-436c-acea-5ef7174dd9be",
			"msmq-group": "46b27aac-aafa-4ffb-b773-e5bf621ee87b",
			"msmq-configuration": "9a0dc344-c100-11d1-bbc5-0080c76670c0",
			"msmq-enterprise-settings": "9a0dc345-c100-11d1-bbc5-0080c76670c0",
			"msmq-migrated-user": "50776997-3c3d-11d2-90cc-00c04fd91ab1",
			"msmq-queue": "9a0dc343-c100-11d1-bbc5-0080c76670c0",
			"msmq-settings": "9a0dc347-c100-11d1-bbc5-0080c76670c0",
			"msmq-site-link": "9a0dc346-c100-11d1-bbc5-0080c76670c0",
			"ms-pki-enterprise-oid": "37cfd85c-6719-4ad8-8f9e-8678ba627563",
			"ms-pki-key-recovery-agent": "26ccf238-a08e-4b86-9a82-a8c9ac7ee5cb",
			"ms-pki-private-key-recovery-agent": "1562a632-44b9-4a7e-a2d3-e426c96a3acc",
			"ms-print-connectionpolicy": "a16f33c7-7fd6-4828-9364-435138fda08d",
			"mssfu-30-domain-info": "36297dce-656b-4423-ab65-dabb2770819e",
			"mssfu-30-mail-aliases": "d6710785-86ff-44b7-85b5-f1f8689522ce",
			"mssfu-30-net-id": "e263192c-2a02-48df-9792-94f2328781a0",
			"mssfu-30-network-user": "e15334a3-0bf0-4427-b672-11f5d84acc92",
			"mssfu-30-nis-map-config": "faf733d0-f8eb-4dcf-8d75-f1753af6a50b",
			"ms-spp-activation-object": "51a0e68c-0dc5-43ca-935d-c1c911bf2ee5",
			"ms-spp-activation-objects-container": "b72f862b-bb25-4d5d-aa51-62c59bdf90ae",
			"ms-tapi-rt-conference": "ca7b9735-4b2a-4e49-89c3-99025334dc94",
			"ms-tapi-rt-person": "53ea1cb5-b704-4df9-818f-5cb4ec86cac1",
			"ms-tpm-information-object": "85045b6a-47a6-4243-a7cc-6890701f662c",
			"ms-tpm-information-objects-container": "e027a8bd-6456-45de-90a3-38593877ee74",
			"ms-wmi-intrangeparam": "50ca5d7d-5c8b-4ef3-b9df-5b66d491e526",
			"ms-wmi-intsetparam": "292f0d9a-cf76-42b0-841f-b650f331df62",
			"ms-wmi-mergeablepolicytemplate": "07502414-fdca-4851-b04a-13645b11d226",
			"ms-wmi-objectencoding": "55dd81c9-c312-41f9-a84d-c6adbdf1e8e1",
			"ms-wmi-policytemplate": "e2bc80f1-244a-4d59-acc6-ca5c4f82e6e1",
			"ms-wmi-policytype": "595b2613-4109-4e77-9013-a3bb4ef277c7",
			"ms-wmi-rangeparam": "45fb5a57-5018-4d0f-9056-997c8c9122d9",
			"ms-wmi-realrangeparam": "6afe8fe2-70bc-4cce-b166-a96f7359c514",
			"ms-wmi-rule": "3c7e6f83-dd0e-481b-a0c2-74cd96ef2a66",
			"ms-wmi-shadowobject": "f1e44bdf-8dd3-4235-9c86-f91f31f5b569",
			"ms-wmi-simplepolicytemplate": "6cc8b2b5-12df-44f6-8307-e74f5cdee369",
			"ms-wmi-som": "ab857078-0142-4406-945b-34c9b6b13372",
			"ms-wmi-stringsetparam": "0bc579a2-1da7-4cea-b699-807f3b9d63a4",
			"ms-wmi-uintrangeparam": "d9a799b2-cef3-48b3-b5ad-fb85f8dd3214",
			"ms-wmi-uintsetparam": "8f4beb31-4e19-46f5-932e-5fa03c339b1d",
			"ms-wmi-unknownrangeparam": "b82ac26b-c6db-4098-92c6-49c18a3336e1",
			"ms-wmi-wmigpo": "05630000-3927-4ede-bf27-ca91f275c26f",
			"nismap": "7672666c-02c1-4f33-9ecf-f649c1dd9b7c",
			"nisnetgroup": "72efbf84-6e7b-4a5c-a8db-8a75a7cad254",
			"nisobject": "904f8a93-4954-4c5f-b1e1-53c097a31e13",
			"ntds-connection": "19195a60-6da0-11d0-afd3-00c04fd930c9",
			"ntds-dsa": "f0f8ffab-1191-11d0-a060-00aa006c33ed",
			"ntds-dsa-ro": "85d16ec1-0791-4bc8-8ab3-70980602ff8c",
			"ntds-service": "19195a5f-6da0-11d0-afd3-00c04fd930c9",
			"ntds-site-settings": "19195a5d-6da0-11d0-afd3-00c04fd930c9",
			"ntfrs-member": "2a132586-9373-11d1-aebc-0000f80367c1",
			"ntfrs-replica-set": "5245803a-ca6a-11d0-afff-0000f80367c1",
			"ntfrs-settings": "f780acc2-56f0-11d1-a9c6-0000f80367c1",
			"ntfrs-subscriber": "2a132588-9373-11d1-aebc-0000f80367c1",
			"ntfrs-subscriptions": "2a132587-9373-11d1-aebc-0000f80367c1",
			"oncrpc": "cadd1e5e-fefc-4f3f-b5a9-70e994204303",
			"organization": "bf967aa3-0de6-11d0-a285-00aa003049e2",
			"organizational-person": "bf967aa4-0de6-11d0-a285-00aa003049e2",
			"organizational-role": "a8df74bf-c5ea-11d1-bbcb-0080c76670c0",
			"organizational-unit": "bf967aa5-0de6-11d0-a285-00aa003049e2",
			"package-registration": "bf967aa6-0de6-11d0-a285-00aa003049e2",
			"person": "bf967aa7-0de6-11d0-a285-00aa003049e2",
			"physical-location": "b7b13122-b82e-11d0-afee-0000f80367c1",
			"pki-certificate-template": "e5209ca2-3bba-11d2-90cc-00c04fd91ab1",
			"pki-enrollment-service": "ee4aa692-3bba-11d2-90cc-00c04fd91ab1",
			"posixaccount": "ad44bb41-67d5-4d88-b575-7b20674e76d8",
			"posixgroup": "2a9350b8-062c-4ed0-9903-dde10d06deba",
			"print-queue": "bf967aa8-0de6-11d0-a285-00aa003049e2",
			"query-policy": "83cc7075-cca7-11d0-afff-0000f80367c1",
			"remote-mail-recipient": "bf967aa9-0de6-11d0-a285-00aa003049e2",
			"remote-storage-service-point": "2a39c5bd-8960-11d1-aebc-0000f80367c1",
			"residential-person": "a8df74d6-c5ea-11d1-bbcb-0080c76670c0",
			"rfc822localpart": "b93e3a78-cbae-485e-a07b-5ef4ae505686",
			"rid-manager": "6617188d-8f3c-11d0-afda-00c04fd930c9",
			"rid-set": "7bfdcb89-4807-11d1-a9c3-0000f80367c1",
			"room": "7860e5d2-c8b0-4cbb-bd45-d9455beb9206",
			"rpc-container": "80212842-4bdc-11d1-a9c4-0000f80367c1",
			"rpc-entry": "bf967aac-0de6-11d0-a285-00aa003049e2",
			"rpc-group": "88611bdf-8cf4-11d0-afda-00c04fd930c9",
			"rpc-profile": "88611be1-8cf4-11d0-afda-00c04fd930c9",
			"rpc-profile-element": "f29653cf-7ad0-11d0-afd6-00c04fd930c9",
			"rpc-server": "88611be0-8cf4-11d0-afda-00c04fd930c9",
			"rpc-server-element": "f29653d0-7ad0-11d0-afd6-00c04fd930c9",
			"rras-administration-connection-point": "2a39c5be-8960-11d1-aebc-0000f80367c1",
			"rras-administration-dictionary": "f39b98ae-938d-11d1-aebd-0000f80367c1",
			"sam-domain": "bf967a90-0de6-11d0-a285-00aa003049e2",
			"sam-domain-base": "bf967a91-0de6-11d0-a285-00aa003049e2",
			"sam-server": "bf967aad-0de6-11d0-a285-00aa003049e2",
			"secret": "bf967aae-0de6-11d0-a285-00aa003049e2",
			"security-object": "bf967aaf-0de6-11d0-a285-00aa003049e2",
			"security-principal": "bf967ab0-0de6-11d0-a285-00aa003049e2",
			"server": "bf967a92-0de6-11d0-a285-00aa003049e2",
			"servers-container": "f780acc0-56f0-11d1-a9c6-0000f80367c1",
			"service-administration-point": "b7b13123-b82e-11d0-afee-0000f80367c1",
			"service-class": "bf967ab1-0de6-11d0-a285-00aa003049e2",
			"service-connection-point": "28630ec1-41d5-11d1-a9c1-0000f80367c1",
			"service-instance": "bf967ab2-0de6-11d0-a285-00aa003049e2",
			"shadowaccount": "5b6d8467-1a18-4174-b350-9cc6e7b4ac8d",
			"simplesecurityobject": "5fe69b0b-e146-4f15-b0ab-c1e5d488e094",
			"site": "bf967ab3-0de6-11d0-a285-00aa003049e2",
			"site-link": "d50c2cde-8951-11d1-aebc-0000f80367c1",
			"site-link-bridge": "d50c2cdf-8951-11d1-aebc-0000f80367c1",
			"sites-container": "7a4117da-cd67-11d0-afff-0000f80367c1",
			"storage": "bf967ab5-0de6-11d0-a285-00aa003049e2",
			"subnet": "b7b13124-b82e-11d0-afee-0000f80367c1",
			"subnet-container": "b7b13125-b82e-11d0-afee-0000f80367c1",
			"subschema": "5a8b3261-c38d-11d1-bbc9-0080c76670c0",
			"top": "bf967ab7-0de6-11d0-a285-00aa003049e2",
			"trusted-domain": "bf967ab8-0de6-11d0-a285-00aa003049e2",
			"type-library": "281416e2-1968-11d0-a28f-00aa003049e2",
			"user": "bf967aba-0de6-11d0-a285-00aa003049e2",
			"volume": "bf967abb-0de6-11d0-a285-00aa003049e2",
		}
		self.aces = {}
		self.computer_sidcache = {}
		self.token_map = {}

		self.curdate = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%S')
		self.zipfilepath = '%s_Bloodhound.zip' %  self.curdate
		self.output_path = output_path
		if output_path is not None:
			self.zipfilepath = os.path.join(output_path, self.zipfilepath)
		self.zipfile = None
		self.MAX_ENTRIES_PER_FILE = 40000
		
		self.totals = {
			'user' : 0,
			'computer' : 0,
			'group' : 0,
			'ou' : 0,
			'gpo' : 0,
			'container' : 0,
			'domain' : 0,
			'trust' : 0
		}
	
	async def print(self, msg:str):
		await self.print_cb(msg)

	
	async def create_progress(self, label, total = None):
		if self.with_progress is True:
			return tqdm(desc = label, total=total)
		else:
			await self.print('[+] %s' % label)
			return None
	
	async def update_progress(self, pbar, value = 1):
		if pbar is None:
			return
		if self.with_progress is True:
			pbar.update(value)
	
	async def close_progress(self, pbar):
		if pbar is None:
			return
		if self.with_progress is True:
			pbar.close()
	
	def get_json_wrapper(self, enumtype):
		return {
			'data' : [],
			'meta': {
				'methods' : 0,
				'type': enumtype,
				'version': 5,
				'count': 0
			}
		}
		

	def split_json(self, enumtype, data):
		if data['meta']['count'] <= self.MAX_ENTRIES_PER_FILE:
			yield data
			return
		
		#split the data
		for i in range(0, data['meta']['count'], self.MAX_ENTRIES_PER_FILE):
			jsonstruct = {
				'data' : [],
				'meta': {
					'methods' : 0,
					'type': enumtype,
					'version': 5,
					'count': 0
				}
			}
			for entry in data['data'][i:i+self.MAX_ENTRIES_PER_FILE]:
				jsonstruct['data'].append(entry)
				jsonstruct['meta']['count'] += 1
			yield jsonstruct

	
	async def write_json_to_zip(self, enumtype, data, filepart = 0):
		if filepart == 0:
			filename = '%s_%s.json' % (self.curdate, enumtype)
		else:
			filename = '%s_%s_%02d.json' % (self.curdate, enumtype, filepart)
		self.zipfile.writestr(filename, json.dumps(data))

	
	async def lookup_dn_children(self, parent_dn):
		parent_dn = parent_dn.upper()
		parent_dn_reversed = reverse_dn_components(parent_dn)
		if parent_dn not in self.DNs:
			logger.debug('[BH] DN not found: %s' % parent_dn_reversed)
			return []

		branch = self.DNs_sorted
		level = 0
		for part in explode_dn(parent_dn_reversed):
			level += 1
			if part not in branch:
				logger.debug('[BH] Part not found: %s Full: %s Branch: %s Level: %s Parts: %s' % (part, parent_dn_reversed, branch.keys(), level, explode_dn(parent_dn_reversed)))
				return []
			branch = branch[part]

		res_dns = []
		for dnpart in branch:
			res_dns.append(dnpart + ',' + parent_dn)
			
		results = []
		for tdn in res_dns:
			if is_filtered_container_child(tdn):
				continue
			if tdn not in self.DNs:
				attrs, err = await self.connection.dnattrs(tdn, ['distinguishedName','objectGUID', 'objectClass','sAMAaccountType', 'sAMAccountName', 'objectSid', 'name'])
				if err is not None:
					raise err
				if attrs is None or len(attrs) == 0:
					logger.debug('[BH] Missing DN: %s' % tdn)
					continue
				res = self.resolve_entry(attrs)
				results.append({
					'ObjectIdentifier': res['objectid'].upper(),
					'ObjectType': res['type'].capitalize(),
				})
				continue
			entry = self.ocache[self.DNs[tdn]]
			results.append({
				'ObjectIdentifier': entry['ObjectIdentifier'].upper(),
				'ObjectType': entry['ObjectType'].capitalize() if entry['ObjectType'].lower() != 'ou' else 'OU',
			})
		
		return results

	async def dump_schema(self):
		pbar = await self.create_progress('Dumping schema')
		# manual stuff here...
		# https://learn.microsoft.com/en-us/windows/win32/adschema/c-foreignsecurityprincipal
		self.schema['foreignsecurityprincipal'] = '89e31c12-8530-11d0-afda-00c04fd930c9'
		
		entries_to_fetch = [
			'ms-Mcs-AdmPwd',
			'ms-LAPS-EncryptedPassword',
			'ms-DS-Key-Credential-Link',
			'Service-Principal-Name',
		]

		for entry_name in entries_to_fetch:
			try:
				entry, err = await self.connection.get_schemaentry_by_name(entry_name, ['name', 'schemaIDGUID'])
				if entry is None:
					continue

				self.schema[entry.name.lower()] = str(entry.schemaIDGUID)
				await self.update_progress(pbar)
			except Exception as e:
				logger.debug('Error fetching schema entry: %s' % e)
				continue

		await self.close_progress(pbar)

	def add_ocache(self, dn, objectid, principal, otype, dns = '', spns = None):
		self.totals[otype] += 1
		if objectid in WELLKNOWN_SIDS:
			objectid = '%s-%s' % (self.domainname.upper(), objectid.upper())
		self.ocache[objectid] = {
			'dn' : dn.upper(),
			'ObjectIdentifier' : objectid,
			'principal' : principal,
			'ObjectType' : otype,
		}
		self.DNs[dn.upper()] = objectid
		if otype == 'computer':
			entry = {
				'ObjectIdentifier' : objectid,
				'ObjectType' : otype
			}
			if dns is None:
				dns = ''
			self.computer_sidcache[dns.lower()] = entry
			if spns is not None:
				for spn in spns:
					target = spn.split('/')[1]
					target = target.split(':')[0]
					self.computer_sidcache[target.lower()] = entry
	
	def resolve_entry(self, entry):
		# I really REALLY did not want to implement this
		resolved = {}
		account = entry.get('sAMAccountName', '')
		dn = entry.get('distinguishedName', '')
		resolved['objectid'] = entry.get('objectSid', '')
		resolved['principal'] = ('%s@%s' % (account, self.domainname)).upper()
		if 'sAMAaccountName' in entry:
			accountType = entry['sAMAccountType']
			object_class = entry['objectClass']
			if accountType in [268435456, 268435457, 536870912, 536870913]:
				resolved['type'] = 'Group'
			elif accountType in [805306368] or \
				 'msDS-GroupManagedServiceAccount' in object_class or \
				 'msDS-ManagedServiceAccount' in object_class:
				resolved['type'] = 'User'
			elif accountType in [805306369]:
				resolved['type'] = 'Computer'
				short_name = account.rstrip('$')
				resolved['principal'] = ('%s.%s' % (short_name, self.domainname)).upper()
			elif accountType in [805306370]:
				resolved['type'] = 'trustaccount'
			else:
				resolved['type'] = 'Domain'
			return resolved
		
		if 'objectGUID' in entry:
			resolved['objectid'] = entry['objectGUID']
			resolved['principal'] = ('%s@%s' % (entry.get('name', ''), self.domainname)).upper()
			object_class = entry.get('objectClass', [])
			if 'organizationalUnit' in object_class:
				resolved['type'] = 'OU'
			elif 'container' in object_class:
				resolved['type'] = 'Container'
			else:
				resolved['type'] = 'Base'
			return resolved

	async def dump_lookuptable(self):
		pbar = await self.create_progress('Generating lookuptable')
		# domains
		adinfo, err = await self.connection.get_ad_info()
		if err is not None:
			raise err
		self.domainsid = adinfo.objectSid
		self.add_ocache(adinfo.distinguishedName, adinfo.objectSid, '', 'domain')
		await self.update_progress(pbar)

		#trusts
		async for entry, err in self.connection.get_all_trusts(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'trust')
			await self.update_progress(pbar)

		#users
		async for entry, err in self.connection.get_all_users(['distinguishedName', 'objectSid', 'objectGUID', 'sAMAccountName']):
			if err is not None:
				raise err
			short_name = entry.sAMAccountName
			self.add_ocache(entry.distinguishedName, entry.objectSid, ('%s@%s' % (short_name, self.domainname)).upper(), 'user')
			await self.update_progress(pbar)

		#machines
		async for entry, err in self.connection.get_all_machines(['distinguishedName', 'objectSid', 'objectGUID', 'sAMAccountName', 'dNSHostName', 'servicePrincipalName']):
			if err is not None:
				raise err
			short_name = entry.sAMAccountName
			dns = entry.dNSHostName
			if dns is None:
				dns = ''

			self.add_ocache(entry.distinguishedName, entry.objectSid, ('%s@%s' % (short_name, self.domainname)).upper(), 'computer', dns, entry.servicePrincipalName)
			await self.update_progress(pbar)

		#groups
		async for entry, err in self.connection.get_all_groups(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectSid, '', 'group')
			await self.update_progress(pbar)

		#ous
		async for entry, err in self.connection.get_all_ous(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'ou')
			await self.update_progress(pbar)

		#containers
		async for entry, err in self.connection.get_all_containers(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			if is_filtered_container(entry.distinguishedName):
				continue
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'container')
			await self.update_progress(pbar)

		#gpos
		async for entry, err in self.connection.get_all_gpos(['distinguishedName', 'objectSid', 'objectGUID']):
			if err is not None:
				raise err
			self.add_ocache(entry.distinguishedName, entry.objectGUID, '', 'gpo')
			await self.update_progress(pbar)

		#foreignsecurityprincipal
		async for entry, err in self.connection.get_all_foreignsecurityprincipals(['name','sAMAccountName', 'objectSid', 'objectGUID', 'distinguishedName', 'objectClass']):
			bhentry = {}
			entry = entry['attributes']
			if 'container' in  entry.get('objectClass', []) is True:
				continue

			if entry['objectSid'] in WELLKNOWN_SIDS:
				bhentry['objectid'] = '%s-%s' % (self.domainname.upper(), entry['objectSid'].upper())
			bhentry['principal'] = self.domainname.upper()
			bhentry['type'] = 'foreignsecurityprincipal'
			if 'name' in entry:
				if entry['name'] in WELLKNOWN_SIDS:
					gname, sidtype = WELLKNOWN_SIDS[entry['name']]
					bhentry['type'] = sidtype.capitalize()
					bhentry['principal'] = '%s@%s' % (gname.upper(), self.domainname.upper())
					bhentry['objectid'] = '%s-%s' % (self.domainname.upper(), entry['objectSid'].upper())
				else:
					bhentry['objectid'] = entry['name']

			self.ocache[bhentry['objectid']] = {
				'dn' : entry['distinguishedName'].upper(),
				'ObjectIdentifier' : bhentry['objectid'],
				'principal' : bhentry['principal'],
				'ObjectType' : bhentry['type'],
			}
			self.DNs[entry['distinguishedName'].upper()] = bhentry['objectid']
			
		await self.close_progress(pbar)

		for dn in [reverse_dn_components(dn) for dn in self.DNs]:
			branch = self.DNs_sorted
			for part in explode_dn(dn):
				if part not in branch:
					branch[part.upper()] = {}
				branch = branch[part.upper()]
		
		if self.debug is True:
			with open('dn.json', 'w') as f:
				json.dump(self.DNs, f, indent=4)

			with open('dntree.json', 'w') as f:
				json.dump(self.DNs_sorted, f, indent=4)
	
	async def dump_acls(self):
		sdbatch = []
		tasks = []
		pbar = await self.create_progress('Dumping SDs', total=len(self.ocache))
		for sid in self.ocache:
			dn = self.ocache[sid]['dn']
			secdesc, err = await self.connection.get_objectacl_by_dn(dn)
			if err is not None:
				raise err
			dn = dn.upper()
			oentry = {
					'IsACLProtected' : None,
					'Properties' : {
						'haslaps' : 'ms-mcs-admpwd' in self.schema
					}
				}
			otype = self.ocache[sid]['ObjectType']
			if otype == 'trust':
				continue
			if otype == 'ou':
				otype = 'organizational-unit'
			if dn.upper() not in self.aces:
				if self.use_mp is True:
					from concurrent.futures import ProcessPoolExecutor
					sdbatch.append((dn, oentry, otype.lower(), secdesc, self.schema))
					if len(sdbatch) > self.mp_sdbatch_length:
						loop = asyncio.get_running_loop()
						with ProcessPoolExecutor() as executor:
							for sde in sdbatch:
								tasks.append(loop.run_in_executor(executor, parse_binary_acl, *sde))
						results = await asyncio.gather(*tasks)
						for dn, aces, relations in results:
							self.aces[dn.upper()] = (aces, relations)
						sdbatch = []
						tasks = []
				else:
					dn, aces, relations = parse_binary_acl(dn, oentry, otype.lower(), secdesc, self.schema)
					self.aces[dn.upper()] = (aces, relations)
			await self.update_progress(pbar)
		
		if len(sdbatch) != 0:
			loop = asyncio.get_running_loop()
			with ProcessPoolExecutor() as executor:
				for sde in sdbatch:
					tasks.append(loop.run_in_executor(executor, parse_binary_acl, *sde))
				results = await asyncio.gather(*tasks)
				for dn, aces, relations in results:
					self.aces[dn.upper()] = (aces, relations)
				sdbatch = []
				tasks = []
		await self.close_progress(pbar)
	
	async def resolve_gplink(self, gplinks):
		if gplinks is None:
			return []

		links = []
		for gplink_dn, options in parse_gplink_string(gplinks):
			link = {}
			link['IsEnforced'] = options == 2
			gplink_dn = gplink_dn.upper()
			if gplink_dn in self.DNs:
				lguid = self.ocache[self.DNs[gplink_dn]]['ObjectIdentifier']
			else:
				attrs, err = await self.connection.dnattrs(gplink_dn.upper(), ['objectGUID', 'objectSid'])
				if err is not None:
					raise err
				if attrs is None or len(attrs) == 0:
					logger.debug('[BH] Missing DN: %s' % gplink_dn)
					continue
				try:
					lguid = attrs['objectGUID']
				except:
					logger.debug('[BH] Missing GUID for %s' % gplink_dn)
					continue
			link['GUID'] = lguid.upper()
			links.append(link)
		return links

	def remove_hidden(self, entry):
		to_del = []
		for k in entry:
			if k.startswith('_'):
				to_del.append(k)
		for k in to_del:
			del entry[k]
		return entry

	async def dump_domains(self):
		pbar = await self.create_progress('Dumping domains', self.totals['domain'])
		adinfo, err = await self.connection.get_ad_info()
		if err is not None:
			raise err
		
		domainentry = adinfo.to_bh(self.domainname)
		
		meta, relations = self.aces[domainentry['Properties']['distinguishedname'].upper()]
		domainentry['IsACLProtected'] = meta['IsACLProtected']
		domainentry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
		domainentry['ChildObjects'] =  await self.lookup_dn_children(domainentry['Properties']['distinguishedname'])
		domainentry['Links'] = await self.resolve_gplink(domainentry['_gPLink'])

		jsonstruct = self.get_json_wrapper('domains')
		filectr = 0
		async for entry, err in self.connection.get_all_trusts():
			if err is not None:
				raise err
			domainentry['Trusts'].append(entry.to_bh())
   
		domainentry = self.remove_hidden(domainentry)
		jsonstruct['data'].append(domainentry)
		jsonstruct['meta']['count'] += 1
		if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
			await self.write_json_to_zip('domains', jsonstruct, filectr)
			jsonstruct = self.get_json_wrapper('domains')
			filectr += 1
		await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('domains', jsonstruct, filectr)
		await self.close_progress(pbar)
		if self.debug is True:
			with open('domains.json', 'w') as f:
				json.dump(jsonstruct, f)
	
	async def dump_users(self):
		pbar = await self.create_progress('Dumping users', self.totals['user'])

		jsonstruct = self.get_json_wrapper('users')
		filectr = 0
		async for ldapentry, err in self.connection.get_all_users():
			if err is not None:
				raise err
			
			entry = ldapentry.to_bh(self.domainname)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			
			if entry['_allowerdtodelegateto'] is not None:
				seen = {}
				for host in entry['_allowerdtodelegateto']:
					try:
						target = host.split('/')[1]
						target = target.split(':')[0]
					except IndexError:
						logger.debug('[BH] Invalid delegation target: %s', host)
						continue
					try:
						sid = self.computer_sidcache[target.lower()]
						if sid['ObjectIdentifier'] in seen:
							continue
						seen[sid['ObjectIdentifier']] = 1
						entry['AllowedToDelegate'].append(sid)
					except KeyError:
						if '.' in target:
							entry['AllowedToDelegate'].append(target.upper())
			entry = self.remove_hidden(entry)

			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('users', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('users')
				filectr += 1
			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('users', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('users.json', 'w') as f:
				json.dump(jsonstruct, f)
	
	async def dump_computers(self):
		pbar = await self.create_progress('Dumping computers', self.totals['computer'])
		jsonstruct = self.get_json_wrapper('computers')
		filectr = 0
		async for ldapentry, err in self.connection.get_all_machines():
			entry = ldapentry.to_bh(self.domainname)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			
			if entry['_allowedtoactonbehalfofotheridentity'] is not None:
				allowedacl = base64.b64decode(entry['_allowedtoactonbehalfofotheridentity'])
				_, entryres, relations = parse_binary_acl(entry['Properties']['distinguishedname'].upper(), entry, 'computer', allowedacl, self.schema)
				
				for ace in resolve_aces(relations, self.domainname, self.domainsid, self.ocache):
					if ace['RightName'] == 'Owner':
						continue
					if ace['RightName'] == 'GenericAll':
						entryres['AllowedToAct'].append({
							'ObjectIdentifier': ace['PrincipalSID'], 
							'ObjectType': ace['PrincipalType'].capitalize()
						})
			
			del entry['_allowedtoactonbehalfofotheridentity']
			if entry['Properties']['allowedtodelegate'] is not None:
				seen = {}
				for host in entry['Properties']['allowedtodelegate']:
					try:
						target = host.split('/')[1]
						target = target.split(':')[0]
					except IndexError:
						logger.debug('[BH] Invalid delegation target: %s', host)
						continue
					try:
						sid = self.computer_sidcache[target.lower()]
						if sid['ObjectIdentifier'] in seen:
							continue
						seen[sid['ObjectIdentifier']] = 1
						entry['AllowedToDelegate'].append(sid)
					except KeyError:
						if '.' in target:
							entry['AllowedToDelegate'].append({
								"ObjectIdentifier": target.upper(),
								"ObjectType": "Computer"
							})

			entry = self.remove_hidden(entry)
			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('computers', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('computers')
				filectr += 1
			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('computers', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('computers.json', 'w') as f:
				json.dump(jsonstruct, f)
   
	async def dump_groups(self):
		pbar = await self.create_progress('Dumping groups', self.totals['group'])
		jsonstruct = self.get_json_wrapper('groups')
		filectr = 0
		async for ldapentry, err in self.connection.get_all_groups():
			entry = ldapentry.to_bh(self.domainname)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			
			if ldapentry.member is not None:
				for member in ldapentry.member:
					if member.upper() in self.DNs:
						oid = self.DNs[member.upper()]
						entry['Members'].append({
							'ObjectIdentifier' : self.ocache[oid]['ObjectIdentifier'],
							'ObjectType' : self.ocache[oid]['ObjectType'].capitalize()
						})
					else:
						if member.find('ForeignSecurityPrincipals') != -1:
							continue
	  
			entry = self.remove_hidden(entry)
			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('groups', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('groups')
				filectr += 1
			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('groups', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('groups.json', 'w') as f:
				json.dump(jsonstruct, f)

	async def dump_gpos(self):
		pbar = await self.create_progress('Dumping GPOs', self.totals['gpo'])
		jsonstruct = self.get_json_wrapper('gpos')
		filectr = 0
		async for ldapentry, err in self.connection.get_all_gpos():
			entry = ldapentry.to_bh(self.domainname, self.domainsid)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)      
			entry = self.remove_hidden(entry)

			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('gpos', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('gpos')
				filectr += 1
			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('gpos', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('gpos.json', 'w') as f:
				json.dump(jsonstruct, f)

	async def dump_ous(self):
		pbar = await self.create_progress('Dumping OUs', self.totals['ou'])
		jsonstruct = self.get_json_wrapper('ous')
		filectr = 0

		async for ldapentry, err in self.connection.get_all_ous():
			if err is not None:
				raise err
			entry = ldapentry.to_bh(self.domainname, self.domainsid)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			entry['ChildObjects'] =  await self.lookup_dn_children(entry['Properties']['distinguishedname'])
			entry['Links'] = await self.resolve_gplink(entry['_gPLink'])
			entry = self.remove_hidden(entry)

			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('ous', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('ous')
				filectr += 1

			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('ous', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('ous.json', 'w') as f:
				json.dump(jsonstruct, f)
	
	async def dump_containers(self):
		pbar = await self.create_progress('Dumping Containers', self.totals['container'])
		jsonstruct = self.get_json_wrapper('containers')
		filectr = 0
		async for ldapentry, err in self.connection.get_all_containers():
			if err is not None:
				raise err
			if is_filtered_container(ldapentry.distinguishedName):
				continue
			entry = ldapentry.to_bh(self.domainname, self.domainsid)
			meta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]
			entry['IsACLProtected'] = meta['IsACLProtected']
			entry['Aces'] = resolve_aces(relations, self.domainname, self.domainsid, self.ocache)
			entry['ChildObjects'] =  await self.lookup_dn_children(entry['Properties']['distinguishedname'])
			entry = self.remove_hidden(entry)

			jsonstruct['data'].append(entry)
			jsonstruct['meta']['count'] += 1
			if jsonstruct['meta']['count'] == self.MAX_ENTRIES_PER_FILE:
				await self.write_json_to_zip('containers', jsonstruct, filectr)
				jsonstruct = self.get_json_wrapper('containers')
				filectr += 1
			await self.update_progress(pbar)
		
		if jsonstruct['meta']['count'] > 0:
			await self.write_json_to_zip('containers', jsonstruct, filectr)
		await self.close_progress(pbar)

		if self.debug is True:
			with open('containers.json', 'w') as f:
				json.dump(jsonstruct, f)

	async def get_trusts(self):
		hosts = []
		async for trust, err in self.connection.get_all_trusts():
			if err is not None:
				raise err
			hostname = trust.name
			sid = str(trust.securityIdentifier) if trust.securityIdentifier is not None else None
			if sid is not None:
				sid = sid.upper()
				hosts.append((hostname, sid))

		await self.print('[+] Found %d trusts' % len(hosts))
		return hosts
	
	async def dump_ldap(self):
		if isinstance(self.ldap_url, str):
			if self.ldap_url.startswith('adexplorer://'):
				self.ldap_url = self.ldap_url[13:]
				await self.print('[+] Parsing ADEXPLORER Snapshot...')
				self.connection = await Snapshot.from_file(self.ldap_url)
				self.ldap_url = self.connection
				await self.print('[+] Parsing done!')

		if isinstance(self.ldap_url, Snapshot) is False:
			if isinstance(self.ldap_url, str):
				factory = LDAPConnectionFactory.from_url(self.ldap_url)
				self.connection = factory.get_client()
				self.connection.keepalive = True
			if isinstance(self.ldap_url, LDAPConnectionFactory):
				self.connection = self.ldap_url.get_client()
				self.connection.keepalive = True
			if isinstance(self.ldap_url, MSLDAPClient):
				self.connection = self.ldap_url
			
			if isinstance(self.ldap_url, MSLDAPClientConnection):
				self.connection = MSLDAPClient(None, None, connection = self.ldap_url)
			
			await self.print('[+] Connecting to LDAP server')
			self.connection.keepalive = True
			_, err = await self.connection.connect()
			if err is not None:
				raise err
			await self.print('[+] Connected to LDAP serrver')
			
			self.ldapinfo = self.connection.get_server_info()
			self.domainname = self.ldapinfo['defaultNamingContext'].upper().replace('DC=','').replace(',','.')
		else:
			self.domainname = self.connection.rootdomain.upper().replace('DC=','').replace(',','.')
		
		await self.dump_schema()
		await self.dump_lookuptable()
		await self.dump_acls()
		with zipfile.ZipFile(self.zipfilepath, 'w', zipfile.ZIP_DEFLATED) as self.zipfile:
			await self.dump_domains()
			await self.dump_users()
			await self.dump_computers()
			await self.dump_groups()
			await self.dump_gpos()
			await self.dump_ous()
			await self.dump_containers()
		await self.print('[+] Bloodhound data saved to %s' % self.zipfilepath)

		trusts = []
		try:
			trusts = await self.get_trusts()
		except Exception as e:
			await self.print('[-] Failed to get trusts: %s' % e)
			trusts = []
		
		return self.zipfilepath, trusts, self.domainsid
	
	async def run(self):
		zipfilepath, trusts, domainsid = await self.dump_ldap()

		if self.follow_trusts is True and len(trusts) > 0:
			seen = {}
			seen[domainsid] = 'SELF'
			filectr = 0
			while len(trusts) > 0:
				hostname, sid = trusts.pop(0)
				filectr += 1
				sid = sid.upper()	
				if sid in seen:
					continue
				seen[sid] = hostname
				await self.print('[+] Found trust %s (%s)' % (hostname, sid))
				await self.print('[+] Connecting to %s (follow_trusts)' % hostname)
				if isinstance(self.ldap_url, str):
					factory = LDAPConnectionFactory.from_url(self.ldap_url)
					client = factory.get_client_newtarget(hostname)
				elif isinstance(self.ldap_url, LDAPConnectionFactory):
					client = self.ldap_url.get_client_newtarget(hostname)
				elif isinstance(self.ldap_url, MSLDAPClient):
					factory = LDAPConnectionFactory.from_ldapconnection(self.ldap_url._con)
					client = factory.get_client_newtarget(hostname)
				elif isinstance(self.ldap_url, MSLDAPClientConnection):
					factory = LDAPConnectionFactory.from_ldapconnection(self.ldap_url)
					client = factory.get_client_newtarget(hostname)
				else:
					raise ValueError('Invalid ldap_url type: %s' % type(self.ldap_url))

				_, err = await client.connect()
				if err is not None:
					await self.print('[-] Failed to connect to %s (%s)' % (hostname, err))
					await self.print('[-] If it\'s a connectivity issue (not auth issue), make sure the hostname resolves to an IP address (eg. modify your /etc/hosts)')
					continue
				
				await self.print('[+] Connected to %s (follow_trusts)' % hostname)
				bh = MSLDAPDump2Bloodhound(
					client,
					progress = self.with_progress,
					output_path = self.output_path,
					use_mp = self.use_mp, 
					print_cb = self.print_cb, 
					follow_trusts = False,
				)
				zipfilepath_new, trusts_new, domainsid_new = await bh.run()
				for trust in trusts_new:
					hostname, sid = trust
					sid = sid.upper()
					if sid not in seen and not any(sid == t[1].upper() for t in trusts):
						trusts.append(trust)
						
				# merge zipfiles
				with zipfile.ZipFile(zipfilepath, 'a') as zipfile_original:
					with zipfile.ZipFile(zipfilepath_new, 'r') as zipfile_new:
						for file in zipfile_new.namelist():
							filename = file.replace('.json', '_%02d.json' % (filectr))
							zipfile_original.writestr(filename, zipfile_new.read(file))
				os.remove(zipfilepath_new)

		return zipfilepath, trusts, domainsid
