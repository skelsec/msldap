#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import enum
from msldap.wintypes.sid import SID
from msldap.wintypes.guid import GUID


class ACCESS_MASK(enum.IntFlag):
	GENERIC_READ = 0x80000000
	GENERIC_WRITE = 0x4000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL = 0x10000000
	MAXIMUM_ALLOWED = 0x02000000
	ACCESS_SYSTEM_SECURITY = 0x01000000
	SYNCHRONIZE = 0x00100000
	WRITE_OWNER = 0x00080000
	WRITE_DACL = 0x00040000
	READ_CONTROL = 0x00020000
	DELETE = 0x00010000
	
#https://docs.microsoft.com/en-us/previous-versions/tn-archive/ff405675(v%3dmsdn.10)
class ADS_ACCESS_MASK(enum.IntFlag):
	CREATE_CHILD   = 0x00000001 #The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to create this type of child object.
	DELETE_CHILD   = 0x00000002 #The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to delete this type of child object.
	
	ACTRL_DS_LIST  = 0x00000004
	SELF           = 0x00000008 #The ObjectType GUID identifies a validated write.
	READ_PROP      = 0x00000010 #The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to read the property or property set.
	WRITE_PROP     = 0x00000020 #The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to write the property or property set.
	
	DELETE_TREE    = 0x00000040
	LIST_OBJECT    = 0x00000080
	CONTROL_ACCESS = 0x00000100 #The ObjectType GUID identifies an extended access right.
	
	DELETE          = 0x00010000
	READ_CONTROL    = 0x00020000
	WRITE_DACL      = 0x00040000
	WRITE_OWNER     = 0x00080000
	SYNCHRONIZE     = 0x00100000
	
	ACCESS_SYSTEM_SECURITY = 0x01000000
	MAXIMUM_ALLOWED        = 0x02000000
	
	GENERIC_ALL     = 0x10000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_WRITE   = 0x40000000
	GENERIC_READ    = 0x80000000

#http://www.kouti.com/tables/baseattributes.htm

ExtendedRightsGUID = { 
	'ee914b82-0a98-11d1-adbb-00c04fd8d5cd' : 'Abandon Replication',
	'440820ad-65b4-11d1-a3da-0000f875ae0d' : 'Add GUID',
	'1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd' : 'Allocate Rids',
	'68b1d179-0d15-4d4f-ab71-46152e79a7bc' : 'Allowed to Authenticate',
	'edacfd8f-ffb3-11d1-b41d-00a0c968f939' : 'Apply Group Policy',
	'0e10c968-78fb-11d2-90d4-00c04f79dc55' : 'Certificate-Enrollment',
	'014bf69c-7b3b-11d1-85f6-08002be74fab' : 'Change Domain Master',
	'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd' : 'Change Infrastructure Master',
	'bae50096-4752-11d1-9052-00c04fc2d4cf' : 'Change PDC',
	'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd' : 'Change Rid Master',
	'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd' : 'Change-Schema-Master',
	'e2a36dc9-ae17-47c3-b58b-be34c55ba633' : 'Create Inbound Forest Trust',
	'fec364e0-0a98-11d1-adbb-00c04fd8d5cd' : 'Do Garbage Collection',
	'ab721a52-1e2f-11d0-9819-00aa0040529b' : 'Domain-Administer-Server',
	'69ae6200-7f46-11d2-b9ad-00c04f79f805' : 'Check Stale Phantoms',
	'3e0f7e18-2c7a-4c10-ba82-4d926db99a3e' : 'Allow a DC to create a clone of itself',
	'2f16c4a5-b98e-432c-952a-cb388ba33f2e' : 'Execute Forest Update Script',
	'9923a32a-3607-11d2-b9be-0000f87a36b2' : 'Add/Remove Replica In Domain',
	'4ecc03fe-ffc0-4947-b630-eb672a8a9dbc' : 'Query Self Quota',
	'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' : 'Replicating Directory Changes',
	'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' : 'Replicating Directory Changes All',
	'89e95b76-444d-4c62-991a-0facbeda640c' : 'Replicating Directory Changes In Filtered Set',
	'1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' : 'Manage Replication Topology',
	'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96' : 'Monitor Active Directory Replication',
	'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' : 'Replication Synchronization',
	'05c74c5e-4deb-43b4-bd9f-86664c2a7fd5' : 'Enable Per User Reversibly Encrypted Password',
	'b7b1b3de-ab09-4242-9e30-9980e5d322f7' : 'Generate Resultant Set of Policy (Logging)',
	'b7b1b3dd-ab09-4242-9e30-9980e5d322f7' : 'Generate Resultant Set of Policy (Planning)',
	'7c0e2a7c-a419-48e4-a995-10180aad54dd' : 'Manage Optional Features for Active Directory',
	'ba33815a-4f93-4c76-87f3-57574bff8109' : 'Migrate SID History',
	'b4e60130-df3f-11d1-9c86-006008764d0e' : 'Open Connector Queue',
	'06bd3201-df3e-11d1-9c86-006008764d0e' : 'Allows peeking at messages in the queue.',
	'4b6e08c3-df3c-11d1-9c86-006008764d0e' : 'msmq-Peek-computer-Journal',
	'4b6e08c1-df3c-11d1-9c86-006008764d0e' : 'Peek Dead Letter',
	'06bd3200-df3e-11d1-9c86-006008764d0e' : 'Receive Message',
	'4b6e08c2-df3c-11d1-9c86-006008764d0e' : 'Receive Computer Journal',
	'4b6e08c0-df3c-11d1-9c86-006008764d0e' : 'Receive Dead Letter',
	'06bd3203-df3e-11d1-9c86-006008764d0e' : 'Receive Journal',
	'06bd3202-df3e-11d1-9c86-006008764d0e' : 'Send Message',
	'a1990816-4298-11d1-ade2-00c04fd8d5cd' : 'Open Address List',
	'1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' : 'Read Only Replication Secret Synchronization',
	'45ec5156-db7e-47bb-b53f-dbeb2d03c40f' : 'Reanimate Tombstones',
	'0bc1554e-0a99-11d1-adbb-00c04fd8d5cd' : 'Recalculate Hierarchy',
	'62dd28a8-7f46-11d2-b9ad-00c04f79f805' : 'Recalculate Security Inheritance',
	'ab721a56-1e2f-11d0-9819-00aa0040529b' : 'Receive As',
	'9432c620-033c-4db7-8b58-14ef6d0bf477' : 'Refresh Group Cache for Logons',
	'1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8' : 'Reload SSL/TLS Certificate',
	'7726b9d5-a4b4-4288-a6b2-dce952e80a7f' : 'Run Protect Admin Groups Task',
	'91d67418-0135-4acc-8d79-c08e857cfbec' : 'Enumerate Entire SAM Domain',
	'ab721a54-1e2f-11d0-9819-00aa0040529b' : 'Send As',
	'ab721a55-1e2f-11d0-9819-00aa0040529b' : 'Send To',
	'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501' : 'Unexpire Password',
	'280f369c-67c7-438e-ae98-1d46f3c6f541' : 'Update Password Not Required Bit',
	'be2bb760-7f46-11d2-b9ad-00c04f79f805' : 'Update Schema Cache',
	'ab721a53-1e2f-11d0-9819-00aa0040529b' : 'Change Password',
	'00299570-246d-11d0-a768-00aa006e0529' : 'Reset Password',
}

PropertySets = {
	'72e39547-7b18-11d1-adef-00c04fd8d5cd' : 'DNS Host Name Attributes',
	'b8119fd0-04f6-4762-ab7a-4986c76b3f9a' : 'Other Domain Parameters (for use by SAM)',
	'c7407360-20bf-11d0-a768-00aa006e0529' : 'Domain Password & Lockout Policies',
	'e45795b2-9455-11d1-aebd-0000f80367c1' : 'Phone and Mail Options',
	'59ba2f42-79a2-11d0-9020-00c04fc2d3cf' : 'General Information',
	'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' : 'Group Membership',
	'ffa6f046-ca4b-4feb-b40d-04dfee722543' : 'MS-TS-GatewayAccess',
	'77b5b886-944a-11d1-aebd-0000f80367c1' : 'Personal Information',
	'91e647de-d96f-4b70-9557-d63ff4f3ccd8' : 'Private Information',
	'e48d0154-bcf8-11d1-8702-00c04fb96050' : 'Public Information',
	'037088f8-0ae1-11d2-b422-00a0c968f939' : 'Remote Access Information',
	'5805bc62-bdc9-4428-a5e2-856a0f4c185e' : 'Terminal Server License Server',
	'4c164200-20c0-11d0-a768-00aa006e0529' : 'Account Restrictions',
	'5f202010-79a5-11d0-9020-00c04fc2d4cf' : 'Logon Information',
	'e45795b3-9455-11d1-aebd-0000f80367c1' : 'Web Information',
}

ValidatedWrites = {
	'bf9679c0-0de6-11d0-a285-00aa003049e2' : 'Add/Remove self as member',
	'72e39547-7b18-11d1-adef-00c04fd8d5cd' : 'Validated write to DNS host name',
	'80863791-dbe9-4eb8-837e-7f0ab55d9ac7' : 'Validated write to MS DS Additional DNS Host Name',
	'd31a8757-2447-4545-8081-3bb610cacbf2' : 'Validated write to MS DS behavior version',
	'f3a64788-5306-11d1-a9c5-0000f80367c1' : 'Validated write to service principal name',
}

class SE_SACL(enum.IntFlag):
	SE_DACL_AUTO_INHERIT_REQ = 0x0100 	#Indicates a required security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
										#For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
	SE_DACL_AUTO_INHERITED = 0x0400     #Indicates a security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
										#For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
	SE_DACL_DEFAULTED = 0x0008			#Indicates a security descriptor with a default DACL. For example, if the creator an object does not specify a DACL, the object receives the default DACL from the access token of the creator. This flag can affect how the system treats the DACL with respect to ACE inheritance. The system ignores this flag if the SE_DACL_PRESENT flag is not set.
										#This flag is used to determine how the final DACL on the object is to be computed and is not stored physically in the security descriptor control of the securable object.
										#To set this flag, use the SetSecurityDescriptorDacl function.
	SE_DACL_PRESENT = 0x0004			#Indicates a security descriptor that has a DACL. If this flag is not set, or if this flag is set and the DACL is NULL, the security descriptor allows full access to everyone.
										#This flag is used to hold the security information specified by a caller until the security descriptor is associated with a securable object. After the security descriptor is associated with a securable object, the SE_DACL_PRESENT flag is always set in the security descriptor control.
										#To set this flag, use the SetSecurityDescriptorDacl function.
	SE_DACL_PROTECTED = 0x1000			#Prevents the DACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
	SE_GROUP_DEFAULTED = 0x0002			#Indicates that the security identifier (SID) of the security descriptor group was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose security descriptor group was set by a default mechanism. To set this flag, use the SetSecurityDescriptorGroup function.
	SE_OWNER_DEFAULTED = 0x0001			#Indicates that the SID of the owner of the security descriptor was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose owner was set by a default mechanism. To set this flag, use the SetSecurityDescriptorOwner function.
	SE_RM_CONTROL_VALID = 0x4000		#Indicates that the resource manager control is valid.
	SE_SACL_AUTO_INHERIT_REQ = 0x0200	#Indicates a required security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
										#The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
	SE_SACL_AUTO_INHERITED = 0x0800		#Indicates a security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
										#The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
	SE_SACL_DEFAULTED = 0x0008			#A default mechanism, rather than the original provider of the security descriptor, provided the SACL. This flag can affect how the system treats the SACL, with respect to ACE inheritance. The system ignores this flag if the SE_SACL_PRESENT flag is not set. To set this flag, use the SetSecurityDescriptorSacl function.
	SE_SACL_PRESENT = 0x0010			#Indicates a security descriptor that has a SACL. To set this flag, use the SetSecurityDescriptorSacl function.
	SE_SACL_PROTECTED = 0x2000			#Prevents the SACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
	SE_SELF_RELATIVE = 0x8000			#Indicates a self-relative security descriptor. If this flag is not set, the security descriptor is in absolute format. For more information, see Absolute and Self-Relative Security Descriptors.

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEType(enum.Enum):	
	ACCESS_ALLOWED_ACE_TYPE = 0x00
	ACCESS_DENIED_ACE_TYPE = 0x01
	SYSTEM_AUDIT_ACE_TYPE = 0x02
	SYSTEM_ALARM_ACE_TYPE = 0x03
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04
	ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
	SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
	SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
	ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D
	SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10 
	SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
	SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
	SYSTEM_SCOPED_POLICY_ID_ACE_TYPE =0x13

class AceFlags(enum.IntFlag):
	CONTAINER_INHERIT_ACE = 0x02
	FAILED_ACCESS_ACE_FLAG = 0x80
	INHERIT_ONLY_ACE = 0x08
	INHERITED_ACE = 0x10
	NO_PROPAGATE_INHERIT_ACE = 0x04
	OBJECT_INHERIT_ACE = 0x01
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
	

	
class ACEReader:
	@staticmethod
	def from_buffer(buff):
		hdr = ACEHeader.pre_parse(buff)
		obj = acetype2ace.get(hdr.AceType)
		if not obj:
			raise Exception('ACE type %s not implemented!' % hdr.AceType)
		return obj.from_buffer(io.BytesIO(buff.read(hdr.AceSize)))

#ACCESS_ALLOWED_ACE	
class ACCESS_ALLOWED_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_ALLOWED_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_ACE\r\n'
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % self.Mask		
		return t
		
class ACCESS_DENIED_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_DENIED_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
class SYSTEM_AUDIT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_AUDIT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
class SYSTEM_ALARM_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_ALARM_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
class ACCESS_ALLOWED_OBJECT_Flags(enum.IntFlag):
	NONE = 0x00000000 #Neither ObjectType nor InheritedObjectType are valid.
	ACE_OBJECT_TYPE_PRESENT = 0x00000001 #ObjectType is valid.
	ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002 #InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.

class ACCESS_ALLOWED_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_ALLOWED_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class ACCESS_DENIED_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_DENIED_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace
		
	def __str__(self):
		t = 'ACCESS_DENIED_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class SYSTEM_AUDIT_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_AUDIT_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class ACCESS_ALLOWED_CALLBACK_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_ALLOWED_CALLBACK_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_CALLBACK_ACE'
		t += 'Header: %s\r\n' % self.Header
		t += 'Mask: %s\r\n' % self.Mask
		t += 'Sid: %s\r\n' % self.Sid
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class ACCESS_DENIED_CALLBACK_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_DENIED_CALLBACK_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'ACCESS_DENIED_CALLBACK_ACE'
		t += 'Header: %s\r\n' % self.Header
		t += 'Mask: %s\r\n' % self.Mask
		t += 'Sid: %s\r\n' % self.Sid
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class ACCESS_ALLOWED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_ALLOWED_CALLBACK_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_CALLBACK_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class ACCESS_DENIED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = ACCESS_DENIED_CALLBACK_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'ACCESS_DENIED_CALLBACK_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class SYSTEM_AUDIT_CALLBACK_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_AUDIT_CALLBACK_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_CALLBACK_ACE'
		t += 'Header: %s\r\n' % self.Header
		t += 'Mask: %s\r\n' % self.Mask
		t += 'Sid: %s\r\n' % self.Sid
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class SYSTEM_AUDIT_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_AUDIT_CALLBACK_OBJECT_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Flags = ACCESS_ALLOWED_OBJECT_Flags(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACCESS_ALLOWED_OBJECT_Flags.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_CALLBACK_OBJECT_ACE'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class SYSTEM_MANDATORY_LABEL_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_MANDATORY_LABEL_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
class SYSTEM_RESOURCE_ATTRIBUTE_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		self.AttributeData = None
		

		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_RESOURCE_ATTRIBUTE_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		ace.AttributeData = buff.read() #not really sure, this will consume the whole buffer! (but we dont know the size at this point!)
		return ace
		
	def __str__(self):
		t = 'SYSTEM_RESOURCE_ATTRIBUTE_ACE'
		t += 'Header: %s\r\n' % self.Header
		t += 'Mask: %s\r\n' % self.Mask
		t += 'Sid: %s\r\n' % self.Sid
		t += 'AttributeData: %s \r\n' % self.AttributeData
		
		return t
		
class SYSTEM_SCOPED_POLICY_ID_ACE:
	def __init__(self):
		self.Header = None
		self.Mask = None
		self.Sid = None
		
	@staticmethod
	def from_buffer(buff):
		ace = SYSTEM_SCOPED_POLICY_ID_ACE()
		ace.Header = ACEHeader.from_buffer(buff)
		ace.Mask = ADS_ACCESS_MASK(int.from_bytes(buff.read(4), 'little', signed = False))
		ace.Sid = SID.from_buffer(buff)
		return ace
		
acetype2ace = {
	ACEType.ACCESS_ALLOWED_ACE_TYPE : ACCESS_ALLOWED_ACE,
	ACEType.ACCESS_DENIED_ACE_TYPE : ACCESS_DENIED_ACE,
	ACEType.SYSTEM_AUDIT_ACE_TYPE : SYSTEM_AUDIT_ACE,
	ACEType.SYSTEM_ALARM_ACE_TYPE : SYSTEM_ALARM_ACE,
	ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE : ACCESS_ALLOWED_OBJECT_ACE,
	ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE : ACCESS_DENIED_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE : SYSTEM_AUDIT_OBJECT_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE : ACCESS_DENIED_CALLBACK_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_DENIED_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE : SYSTEM_MANDATORY_LABEL_ACE,
	ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE : SYSTEM_RESOURCE_ATTRIBUTE_ACE,
	ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE : SYSTEM_SCOPED_POLICY_ID_ACE,
	}
"""
ACEType.ACCESS_ALLOWED_COMPOUND_ACE_TYPE : ,# reserved
ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE : , # reserved
ACEType.SYSTEM_ALARM_CALLBACK_ACE_TYPE : ,# reserved
ACEType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE : ,# reserved

"""

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEHeader:
	def __init__(self):
		self.AceType = None
		self.AceFlags = None
		self.AceSize = None
		
	@staticmethod
	def from_bytes(data):
		return ACEHeader.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		return hdr
		
	@staticmethod
	def pre_parse(buff):
		pos = buff.tell()
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		buff.seek(pos,0)
		return hdr


class ACL:
	def __init__(self):
		self.AclRevision = None
		self.Sbz1 = None
		self.AclSize = None
		self.AceCount = None
		self.Sbz2 = None
		
		self.aces = []
		
	@staticmethod
	def from_buffer(buff):
		acl = ACL()
		acl.AclRevision = int.from_bytes(buff.read(1), 'little', signed = False)
		acl.Sbz1 = int.from_bytes(buff.read(1), 'little', signed = False)
		acl.AclSize = int.from_bytes(buff.read(2), 'little', signed = False)
		acl.AceCount = int.from_bytes(buff.read(2), 'little', signed = False)
		acl.Sbz2 = int.from_bytes(buff.read(2), 'little', signed = False)
		for _ in range(acl.AceCount):
			acl.aces.append(ACEReader.from_buffer(buff))
		return acl
		
	def __str__(self):
		t = '=== ACL ===\r\n'
		for ace in self.aces:
			t += '%s\r\n' % str(ace)
		return t

#https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_security_descriptor
class SECURITY_DESCRIPTOR:
	def __init__(self):
		self.Revision = None
		self.Sbz1 = None
		self.Control = None
		self.Owner = None
		self.Group = None
		self.Sacl = None
		self.Dacl = None
	
	@staticmethod
	def from_bytes(data):
		return SECURITY_DESCRIPTOR.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		sd = SECURITY_DESCRIPTOR()
		sd.Revision = int.from_bytes(buff.read(1), 'little', signed = False)
		sd.Sbz1 =  int.from_bytes(buff.read(1), 'little', signed = False)
		sd.Control = SE_SACL(int.from_bytes(buff.read(2), 'little', signed = False))
		OffsetOwner  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetGroup  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetSacl  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetDacl  = int.from_bytes(buff.read(4), 'little', signed = False)
		if OffsetOwner > 0:
			buff.seek(OffsetOwner)
			sd.Owner = SID.from_buffer(buff)
		
		if OffsetGroup > 0:
			buff.seek(OffsetGroup)
			sd.Group = SID.from_buffer(buff)
			
		if OffsetSacl > 0:
			buff.seek(OffsetSacl)
			sd.Sacl = ACL.from_buffer(buff)
		
		if OffsetDacl > 0:
			buff.seek(OffsetDacl)
			sd.Dacl = ACL.from_buffer(buff)
			
		return sd
			
			
	def __str__(self):
		t = '=== SECURITY_DESCRIPTOR ==\r\n'
		t+= 'Revision : %s\r\n' % self.Revision
		t+= 'Control : %s\r\n' % self.Control
		t+= 'Owner : %s\r\n' % self.Owner
		t+= 'Group : %s\r\n' % self.Group
		t+= 'Sacl : %s\r\n' % self.Sacl
		t+= 'Dacl : %s\r\n' % self.Dacl
		return t
	