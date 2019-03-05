import io
import enum
from .sid import *

class GUID:
	def __init__(self):
		self.Data1 = None
		self.Data2 = None
		self.Data3 = None
		self.Data4 = None
		
	@staticmethod
	def from_buffer(buff):
		guid = GUID()
		guid.Data1 = buff.read(4)
		guid.Data2 = buff.read(2)
		guid.Data3 = buff.read(2)
		guid.Data4 = buff.read(8)
		return guid
		
	@staticmethod
	def from_string(str):
		guid = GUID()
		guid.Data1 = bytes.fromhex(str.split('-')[0])
		guid.Data2 = bytes.fromhex(str.split('-')[1])
		guid.Data3 = bytes.fromhex(str.split('-')[2])
		guid.Data4 = bytes.fromhex(str.split('-')[3])
		return guid			
		
	def __str__(self):
		return '-'.join([self.Data1.hex(), self.Data2.hex(),self.Data3.hex(),self.Data4.hex()])

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
	
class ADS_ACCESS_MASK(enum.IntFlag):
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
	ADS_RIGHT_DS_CONTROL_ACCESS = 0X00000100 #The ObjectType GUID identifies an extended access right.
	ADS_RIGHT_DS_CREATE_CHILD = 0X00000001 #The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to create this type of child object.
	ADS_RIGHT_DS_DELETE_CHILD = 0X00000002 #The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to delete this type of child object.
	ADS_RIGHT_DS_READ_PROP = 0x00000010 #The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to read the property or property set.
	ADS_RIGHT_DS_WRITE_PROP = 0x00000020 #The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to write the property or property set.
	ADS_RIGHT_DS_SELF = 0x00000008 #The ObjectType GUID identifies a validated write.

	

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
		
acetype2ace = {
	ACEType.ACCESS_ALLOWED_ACE_TYPE : ACCESS_ALLOWED_ACE,
	ACEType.ACCESS_DENIED_ACE_TYPE : ACCESS_DENIED_ACE,
	ACEType.SYSTEM_AUDIT_ACE_TYPE : SYSTEM_AUDIT_ACE,
	ACEType.SYSTEM_ALARM_ACE_TYPE : SYSTEM_ALARM_ACE,
	ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE : ACCESS_ALLOWED_OBJECT_ACE,
	}
"""
ACEType.ACCESS_ALLOWED_COMPOUND_ACE_TYPE : ,
ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE : ,
ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE : ,
ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE : ,
ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE : ,
ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE : ,
ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE : ,
ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE : ,
ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE : ,
ACEType.SYSTEM_ALARM_CALLBACK_ACE_TYPE : ,
ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE : ,
ACEType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE : ,
ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE : ,
ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE : ,
ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE : ,
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
		print(acl.AceCount)
		for i in range(acl.AceCount):
			print(i)
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
	