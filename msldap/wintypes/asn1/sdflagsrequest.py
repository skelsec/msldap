#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum
from asn1crypto import core

class SDFlagsRequest(enum.IntFlag):
	OWNER_SECURITY_INFORMATION = 0x1 #Owner identifier of the object.(OSI)
	GROUP_SECURITY_INFORMATION = 0x2 #Primary group identifier.(GSI)
	DACL_SECURITY_INFORMATION = 0x4 #Discretionary access control list (DACL) of the object.(DSI)
	SACL_SECURITY_INFORMATION = 0x8 #System access control list (SACL) of the object.(SSI) 

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0
class SDFlagsRequestValue(core.Sequence):
	_fields = [
		('Flags', core.Integer),
	]