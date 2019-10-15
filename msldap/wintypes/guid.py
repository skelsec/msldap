#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

# https://docs.microsoft.com/en-us/previous-versions/aa373931(v%3Dvs.80)
# Dear Microsoft ppl, pls fuck youselves...
class GUID:
	def __init__(self):
		self.Data1 = None
		self.Data2 = None
		self.Data3 = None
		self.Data4 = None
		
	@staticmethod
	def from_buffer(buff):
		guid = GUID()
		guid.Data1 = buff.read(4)[::-1]
		guid.Data2 = buff.read(2)[::-1]
		guid.Data3 = buff.read(2)[::-1]
		guid.Data4 = buff.read(8)
		return guid
		
	@staticmethod
	def from_string(str):
		guid = GUID()
		guid.Data1 = bytes.fromhex(str.split('-')[0])
		guid.Data2 = bytes.fromhex(str.split('-')[1])
		guid.Data3 = bytes.fromhex(str.split('-')[2])
		guid.Data4 = bytes.fromhex(str.split('-')[3])
		guid.Data4 += bytes.fromhex(str.split('-')[4])
		return guid			
		
	def __str__(self):
		return '-'.join([self.Data1.hex(), self.Data2.hex(),self.Data3.hex(),self.Data4[:2].hex(),self.Data4[2:].hex()])