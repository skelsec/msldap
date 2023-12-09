
# The following code was heavily inspired by the 
# ADExplorerSnapshot.py project created by c3c
# 
# The project was licensed under MIT at the time
# of creating this script, but did not include a
# LICENSE.md file
# https://github.com/c3c/ADExplorerSnapshot.py

import io
import struct
import enum
import calendar
from datetime import datetime
from typing import Dict, List

from msldap import logger
from msldap.ldap_objects import MSADSchemaEntry, MSADInfo_ATTRS, MSADInfo, MSADContainer, MSADContainer_ATTRS, \
    MSADDomainTrust_ATTRS, MSADDomainTrust, MSADOU, MSADOU_ATTRS, MSADUser, MSADUser_ATTRS, MSADGroup, MSADGroup_ATTRS,\
    MSADMachine_ATTRS, MSADMachine, MSADGPO_ATTRS, MSADGPO

from msldap.protocol.typeconversion import MSLDAP_BUILTIN_ATTRIBUTE_TYPES, LDAP_WELL_KNOWN_ATTRS

ENCODER_SPEFIFIC_FULCTIONS = [
    'single_bool', 'single_str', 'multi_str'
]

class ADSTYPE(enum.Enum):
    INVALID = 0
    DN_STRING = 1
    CASE_EXACT_STRING = 2
    CASE_IGNORE_STRING = 3
    PRINTABLE_STRING = 4
    NUMERIC_STRING = 5
    BOOLEAN = 6
    INTEGER = 7
    OCTET_STRING = 8
    UTC_TIME = 9
    LARGE_INTEGER = 10
    PROV_SPECIFIC = 11
    OBJECT_CLASS = 12
    CASEIGNORE_LIST = 13
    OCTET_LIST = 14
    PATH = 15
    POSTALADDRESS = 16
    TIMESTAMP = 17
    BACKLINK = 18
    TYPEDNAME = 19
    HOLD = 20
    NETADDRESS = 21
    REPLICAPOINTER = 22
    FAXNUMBER = 23
    EMAIL = 24
    NT_SECURITY_DESCRIPTOR = 25
    UNKNOWN = 26
    DN_WITH_BINARY = 27
    DN_WITH_STRING = 28

class SystemTime:
    def __init__(self):
        self.year = None
        self.month = None
        self.dayOfWeek = None
        self.day = None
        self.hour = None
        self.minute = None
        self.second = None
        self.milliseconds = None
    
    @staticmethod
    def from_bytes(data:bytes):
        return SystemTime.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_buffer(buff):
        st = SystemTime()
        st.year = struct.unpack("<H", buff.read(2))[0]
        st.month = struct.unpack("<H", buff.read(2))[0]
        st.dayOfWeek = struct.unpack("<H", buff.read(2))[0]
        st.day = struct.unpack("<H", buff.read(2))[0]
        st.hour = struct.unpack("<H", buff.read(2))[0]
        st.minute = struct.unpack("<H", buff.read(2))[0]
        st.second = struct.unpack("<H", buff.read(2))[0]
        st.milliseconds = struct.unpack("<H", buff.read(2))[0]
        return st
    
    def to_datetime(self, is_utc=True):
        return datetime(self.year, self.month, self.day, self.hour, self.minute, self.second, self.milliseconds*1000, tzinfo=None)

    def to_unixtime(self):
        return calendar.timegm(self.to_datetime().timetuple())
    
    def __str__(self):
        t = '== SystemTime ==\r\n'
        t += 'year: %s\r\n' % self.year
        t += 'month: %s\r\n' % self.month
        t += 'dayOfWeek: %s\r\n' % self.dayOfWeek
        t += 'day: %s\r\n' % self.day
        t += 'hour: %s\r\n' % self.hour
        t += 'minute: %s\r\n' % self.minute
        t += 'second: %s\r\n' % self.second
        t += 'milliseconds: %s\r\n' % self.milliseconds
        return t

class Right:
    def __init__(self):
        self.lenRightName = None
        self.rightName = None
        self.lenDescription = None
        self.description = None
        self.blob = None
        self._pos = None
        self._idx = None

    def get_meta(self, idx:int, pos:int):
        r = Right()
        r._idx = idx
        r.rightName = self.rightName
        r.description = self.description
        r.blob = self.blob
        r._pos = pos
        return r

    @staticmethod
    def from_bytes(data:bytes):
        return Right.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_buffer(buff):
        right = Right()
        right.lenRightName = struct.unpack("<I", buff.read(4))[0]
        right.rightName = buff.read(right.lenRightName).decode('utf-16-le').strip('\x00')
        right.lenDescription = struct.unpack("<I", buff.read(4))[0]
        right.description = buff.read(right.lenDescription).decode('utf-16-le').strip('\x00')
        right.blob = buff.read(20)
        return right

class AuxiliaryClasses:
    def __init__(self):
        self.lenAuxiliaryClass = None
        self.auxiliaryClass = None
    
    @staticmethod
    def from_bytes(data:bytes):
        return AuxiliaryClasses.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_buffer(buff):
        aux = AuxiliaryClasses()
        aux.lenAuxiliaryClass = struct.unpack("<I", buff.read(4))[0]
        aux.auxiliaryClass = buff.read(aux.lenAuxiliaryClass).decode('utf-16-le').strip('\x00')
        return aux

class SystemPossSuperior:
    def __init__(self):
        self.lenSystemPossSuperior = None
        self.systemPossSuperior = None
    
    @staticmethod
    def from_bytes(data:bytes):
        return SystemPossSuperior.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_buffer(buff):
        sps = SystemPossSuperior()
        sps.lenSystemPossSuperior = struct.unpack("<I", buff.read(4))[0]
        sps.systemPossSuperior = buff.read(sps.lenSystemPossSuperior).decode('utf-16-le').strip('\x00')
        return sps

class Block:
    def __init__(self):
        self.unk1 = None
        self.unk2 = None
        self.unk3 = None
    
    @staticmethod
    def from_bytes(data:bytes):
        return Block.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_buffer(buff):
        block = Block()
        block.unk1 = struct.unpack("<I", buff.read(4))[0]
        block.unk2 = struct.unpack("<I", buff.read(4))[0]
        block.unk3 = buff.read(block.unk2).decode('utf-16-le').strip('\x00')
        return block
    
class Class:
    def __init__(self):
        self.lenClassName = None
        self.className = None
        self.lenDN = None
        self.DN = None
        self.lenCommonClassName = None
        self.commonClassName = None
        self.lenSubClassOf = None
        self.subClassOf = None
        self.schemaIDGUID = None
        self.offsetToNumBlocks = None
        self.unk2 = None
        self.numBlocks = None
        self.blocks = None
        self.numExtraShiz = None
        self.extraShiz = None
        self.numSystemPossSuperiors = None
        self.systemPossSuperiors = None
        self.numAuxiliaryClasses = None
        self.auxiliaryClasses = None
        self._idx = None
        self._pos = None

    def get_meta(self, idx:int, pos:int):
        cls = Class()
        cls._idx = idx
        cls._pos = pos
        cls.className = self.className
        cls.DN = self.DN
        cls.commonClassName = self.commonClassName
        cls.subClassOf = self.subClassOf
        cls.schemaIDGUID = self.schemaIDGUID
        cls.unk2 = self.unk2
        cls.blocks = self.blocks
        cls.extraShiz = self.extraShiz
        cls.systemPossSuperiors = self.systemPossSuperiors
        cls.auxiliaryClasses = self.auxiliaryClasses
        return cls

    @staticmethod
    def from_bytes(data:bytes):
        return Class.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_buffer(buff):
        cls = Class()
        cls.lenClassName = struct.unpack("<I", buff.read(4))[0]
        cls.className = buff.read(cls.lenClassName).decode('utf-16-le').strip('\x00')
        cls.lenDN = struct.unpack("<I", buff.read(4))[0]
        cls.DN = buff.read(cls.lenDN).decode('utf-16-le').strip('\x00')
        cls.lenCommonClassName = struct.unpack("<I", buff.read(4))[0]
        cls.commonClassName = buff.read(cls.lenCommonClassName).decode('utf-16-le').strip('\x00')
        cls.lenSubClassOf = struct.unpack("<I", buff.read(4))[0]
        cls.subClassOf = buff.read(cls.lenSubClassOf).decode('utf-16-le').strip('\x00')
        cls.schemaIDGUID = buff.read(16)
        cls.offsetToNumBlocks = struct.unpack("<I", buff.read(4))[0]
        cls.unk2 = buff.read(cls.offsetToNumBlocks)
        cls.numBlocks = struct.unpack("<I", buff.read(4))[0]
        cls.blocks = []
        for i in range(cls.numBlocks):
            cls.blocks.append(Block.from_buffer(buff))
        cls.numExtraShiz = struct.unpack("<I", buff.read(4))[0]
        cls.extraShiz = buff.read(cls.numExtraShiz*0x10)
        cls.numSystemPossSuperiors = struct.unpack("<I", buff.read(4))[0]
        cls.systemPossSuperiors = []
        for i in range(cls.numSystemPossSuperiors):
            cls.systemPossSuperiors.append(SystemPossSuperior.from_buffer(buff))
        cls.numAuxiliaryClasses = struct.unpack("<I", buff.read(4))[0]
        cls.auxiliaryClasses = []
        for i in range(cls.numAuxiliaryClasses):
            cls.auxiliaryClasses.append(AuxiliaryClasses.from_buffer(buff))
        return cls

class Property:
    def __init__(self):
        self.lenPropName = None
        self.propName = None
        self.unk1 = None
        self.adsType = None
        self.lenDN = None
        self.DN = None
        self.schemaIDGUID = None
        self.attributeSecurityGUID = None
        self.blob = None
        self._idx = None
        self._pos = None
    
    def get_meta(self, idx:int, pos:int):
        p = Property()
        p._idx = idx
        p._pos = pos
        p.propName = self.propName
        p.adsType = self.adsType
        p.DN = self.DN
        p.schemaIDGUID = self.schemaIDGUID
        if p.attributeSecurityGUID is not None:
            p.attributeSecurityGUID = self.attributeSecurityGUID
        if self.blob is not None:
            p.blob = self.blob
        return p

    @staticmethod
    def from_bytes(data:bytes):
        return Property.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_buffer(buff):
        prop = Property()
        prop.lenPropName = struct.unpack("<I", buff.read(4))[0]
        prop.propName = buff.read(prop.lenPropName).decode('utf-16-le').strip('\x00')
        prop.unk1 = struct.unpack("<I", buff.read(4))[0]
        prop.adsType = struct.unpack("<I", buff.read(4))[0]
        prop.lenDN = struct.unpack("<I", buff.read(4))[0]
        prop.DN = buff.read(prop.lenDN).decode('utf-16-le').strip('\x00')
        prop.schemaIDGUID = buff.read(16)
        prop.attributeSecurityGUID = buff.read(16)
        prop.blob = buff.read(4)
        try:
            prop.adsType = ADSTYPE(prop.adsType)
        except:
            prop.adsType = ADSTYPE.UNKNOWN
        return prop
    
    def __str__(self):
        t = '== Property ==\r\n'
        t += 'lenPropName: %s\r\n' % self.lenPropName
        t += 'propName: %s\r\n' % self.propName
        t += 'unk1: %s\r\n' % self.unk1
        t += 'adsType: %s\r\n' % self.adsType
        t += 'lenDN: %s\r\n' % self.lenDN
        t += 'DN: %s\r\n' % self.DN
        t += 'schemaIDGUID: %s\r\n' % self.schemaIDGUID
        t += 'attributeSecurityGUID: %s\r\n' % self.attributeSecurityGUID
        t += 'blob: %s\r\n' % self.blob
        return t

class Header:
    def __init__(self):
        self.winAdSig = None
        self.marker = None
        self.filetime = None
        self.optionalDescription = None
        self.server = None
        self.numObjects = None
        self.numAttributes = None
        self.fileoffsetLow = None
        self.fileoffsetHigh = None
        self.fileoffsetEnd = None
        self.unk0x43a = None
        self.mappingOffset = None
    
    @staticmethod
    def from_bytes(data:bytes):
        return Header.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_buffer(buff):
        header = Header()
        header.winAdSig = buff.read(10)
        header.marker = struct.unpack("<i", buff.read(4))[0]
        header.filetime = struct.unpack("<Q", buff.read(8))[0]
        header.optionalDescription = buff.read(260*2).decode('utf-16-le').strip('\x00')
        header.server = buff.read(260*2).decode('utf-16-le').strip('\x00')
        header.numObjects = struct.unpack("<I", buff.read(4))[0]
        header.numAttributes = struct.unpack("<I", buff.read(4))[0]
        header.fileoffsetLow = struct.unpack("<I", buff.read(4))[0]
        header.fileoffsetHigh = struct.unpack("<I", buff.read(4))[0]
        header.fileoffsetEnd = struct.unpack("<I", buff.read(4))[0]
        header.unk0x43a = struct.unpack("<i", buff.read(4))[0]
        header.mappingOffset = (header.fileoffsetHigh << 32) | header.fileoffsetLow
        return header
    
    def __str__(self):
        t = '== Header ==\r\n'
        t += 'winAdSig: %s\r\n' % self.winAdSig
        t += 'marker: %s\r\n' % self.marker
        t += 'filetime: %s\r\n' % self.filetime
        t += 'optionalDescription: %s\r\n' % self.optionalDescription
        t += 'server: %s\r\n' % self.server
        t += 'numObjects: %s\r\n' % self.numObjects
        t += 'numAttributes: %s\r\n' % self.numAttributes
        t += 'fileoffsetLow: %s\r\n' % self.fileoffsetLow
        t += 'fileoffsetHigh: %s\r\n' % self.fileoffsetHigh
        t += 'fileoffsetEnd: %s\r\n' % self.fileoffsetEnd
        t += 'unk0x43a: %s\r\n' % self.unk0x43a
        return t

class LDIFIdx:
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.length = end - start

class DatEntry:
    def __init__(self):
        self._fh = None
        self._pos = None
        self._attridx = None
        self._bhcache = {}
        self.objSize = None
        self.tableSize = None
        self.mappingTable = {}


    @staticmethod
    def from_bytes(data:bytes, attridx):
        return DatEntry.from_buffer(io.BytesIO(data), attridx)
    
    @staticmethod
    def from_buffer(buff, attridx):
        de = DatEntry()
        de._fh = buff
        de._pos = buff.tell()
        de._attridx = attridx
        de.objSize = struct.unpack("<I", buff.read(4))[0]
        de.tableSize = struct.unpack("<I", buff.read(4))[0]
        for _ in range(de.tableSize):
            attrIndex = struct.unpack("<I", buff.read(4))[0]
            attrOffset = struct.unpack("<i", buff.read(4))[0]
            de.mappingTable[attrIndex] = attrOffset
        return de

    def resolve_attribute_name(self, attribute):
        if attribute in self._attridx:
            aidx = None
            if self._attridx[attribute] in self.mappingTable:
                aidx = self._attridx[attribute]
                prop = self._attridx[aidx]
            elif self._attridx[self._attridx[attribute]] in self.mappingTable:
                aidx = self._attridx[self._attridx[attribute]]
                prop = self._attridx[aidx]
            if aidx is None:
                return None, None
            return aidx, prop
        return None, None

    def get_attribute(self, attribute):
        aidx, prop = self.resolve_attribute_name(attribute)
        if aidx is None:
            return None
        
        fileAttrOffset = self._pos + self.mappingTable[aidx]
        self._fh.seek(fileAttrOffset)
        numValues = struct.unpack("<I", self._fh.read(4))[0]
        values = []

        if prop.adsType in [ADSTYPE.DN_STRING, ADSTYPE.CASE_IGNORE_STRING, ADSTYPE.CASE_IGNORE_STRING, ADSTYPE.PRINTABLE_STRING, ADSTYPE.NUMERIC_STRING, ADSTYPE.OBJECT_CLASS]:
            offsets = []
            for _ in range(numValues):
                offsets.append(struct.unpack("<I", self._fh.read(4))[0])
            
            for offset in offsets:
                self._fh.seek(fileAttrOffset + offset)
                res = b''
                while True:
                    c = self._fh.read(2)
                    if c == b'\x00\x00':
                        break
                    res += c
                values.append(res)
        
        elif prop.adsType == ADSTYPE.OCTET_STRING:
            lengths = []
            for _ in range(numValues):
                lengths.append(struct.unpack("<I", self._fh.read(4))[0])
            
            for length in lengths:
                raw_val = self._fh.read(length)
                values.append(raw_val)
        
        elif prop.adsType == ADSTYPE.BOOLEAN:
            for _ in range(numValues):
                values.append(str(bool(struct.unpack("<I", self._fh.read(4))[0])).upper().encode('utf-16-le'))
        
        elif prop.adsType == ADSTYPE.INTEGER:
            for _ in range(numValues):
                values.append(struct.unpack("<I", self._fh.read(4))[0])
        
        elif prop.adsType == ADSTYPE.UTC_TIME:
            for _ in range(numValues):
                values.append(SystemTime.from_buffer(self._fh).to_datetime())
        
        elif prop.adsType == ADSTYPE.LARGE_INTEGER:
            for _ in range(numValues):
                values.append(struct.unpack("<Q", self._fh.read(8))[0])

        elif prop.adsType == ADSTYPE.NT_SECURITY_DESCRIPTOR:
            for _ in range(numValues):
                length = struct.unpack("<I", self._fh.read(4))[0]
                values.append(self._fh.read(length))

        fconvert = None
        if prop.propName in MSLDAP_BUILTIN_ATTRIBUTE_TYPES:
            fconvert = MSLDAP_BUILTIN_ATTRIBUTE_TYPES[prop.propName]
        elif prop.propName in LDAP_WELL_KNOWN_ATTRS:
            fconvert = LDAP_WELL_KNOWN_ATTRS[prop.propName]
        
        if fconvert is not None:
            if fconvert.__name__ == 'single_date':
                return values[0]
            if fconvert.__name__ == 'multi_date':
                return values
            if fconvert.__name__ in ENCODER_SPEFIFIC_FULCTIONS:
                return fconvert(values, encoding='utf-16-le')
            return fconvert(values)
        
        logger.debug('[ADEXPLORER] No parser found for property "%s"' % prop.propName)
        return values
    
    def get_all_attributes(self):
        res = []
        for aidx in self.mappingTable:
            prop = self._attridx[aidx]
            res.append((prop.propName, self.get_attribute(prop.propName)))
        return res
    
    def __getitem__(self, item):
        if item == '*':
            return self.get_all_attributes()
        return self.get_attribute(item)
    
    def get(self, item, default=None):
        if item == '*':
            res = self.get_all_attributes()
            if len(res) == 0:
                return default
            return res
        res = self.get_attribute(item)
        if res is None:
            return default
        return res

class Snapshot:
    def __init__(self, max_cache_size:int = 100000):
        self.filename:str = None
        self.filehandle = None
        self.header:Header = None
        self.max_cache_size = max_cache_size

        # All object's DN strings mapped to DatEntry
        self.dn_index:Dict[str, DatEntry] = {}

        # All properties/classes/rights index mapped to the corresponding object
        # Also, the name of each object is mapped to their index number
        # It's a bit of a mess
        self.attr_index = {}

        # Hope we'll never encounter a file with multiple 'domain' class entry
        self.rootdomain = None
    
    @staticmethod
    async def from_file(filename:str):
        sn = Snapshot()
        sn.filename = filename
        sn.filehandle = open(filename, 'rb')
        await sn.parse()
        return sn
    
    async def parse(self):
        self.filehandle.seek(0)
        self.header = Header.from_buffer(self.filehandle)
        await self.build_index()

    async def build_index(self):
        logger.debug('[ADEXPLORER] Building index...')
        self.filehandle.seek(self.header.mappingOffset, io.SEEK_SET)

        logger.debug('[ADEXPLORER] Parsing Properties...')
        # Properties begin
        numattrs = struct.unpack("<I", self.filehandle.read(4))[0]
        attridx = 0
        for _ in range(numattrs):
            pos = self.filehandle.tell()
            prop = Property.from_buffer(self.filehandle)
            self.attr_index[attridx] = prop.get_meta(attridx, pos)
            self.attr_index[self.attr_index[attridx].propName] = attridx
            attridx += 1

        logger.debug('[ADEXPLORER] Parsing Classes...')
        # Classes begin
        numclasses = struct.unpack("<I", self.filehandle.read(4))[0]
        for _ in range(numclasses):
            pos = self.filehandle.tell()
            cls = Class.from_buffer(self.filehandle)
            self.attr_index[attridx] = cls.get_meta(attridx, pos)
            self.attr_index[self.attr_index[attridx].className] = attridx
            attridx += 1
        
        logger.debug('[ADEXPLORER] Parsing Rights...')
        # Rights begin
        numrights = struct.unpack("<I", self.filehandle.read(4))[0]
        for _ in range(numrights):
            pos = self.filehandle.tell()
            right = Right.from_buffer(self.filehandle)
            self.attr_index[attridx] = right.get_meta(attridx, pos)
            attridx += 1
        
        logger.debug('[ADEXPLORER] Meta index built!')
        logger.debug('[ADEXPLORER] Building DN index...')
        self.filehandle.seek(0x43e)
        for _ in range(self.header.numObjects):
            pos = self.filehandle.tell()
            de = DatEntry.from_buffer(self.filehandle, self.attr_index)
            dn = de['distinguishedName'].upper()
            de._bhcache['objectCategory'] = de.get('objectCategory', '')
            de._bhcache['sAMAccountType'] = de.get('sAMAccountType', [])
            de._bhcache['objectClass'] = de.get('objectClass', [])
            #de._bhcache['objectSid'] = de.get('objectSid', None)
            #de._bhcache['objectGUID'] = de.get('objectGUID', None)
            if self.rootdomain is None and 'domain' in de._bhcache['objectClass']:
                self.rootdomain = dn
            self.dn_index[dn] = de
            self.filehandle.seek(pos+de.objSize)

    #### DEBUG STUFF HERE ####
    async def attr_lookup(self, attr):
        #searches all objects who have this attribute
        #returns a list of DNs
        if attr not in self.attr_index:
            return
        
        attridx = self.attr_index[attr]
        prop = self.attr_index[attridx]

        for dn in self.dn_index:
            if attridx in self.dn_index[dn].mappingTable:
                yield dn

    async def sid_lookup(self, sid):
        for dn in self.dn_index:
            if sid == self.dn_index[dn]['objectSid']:
                print(dn)
    
    #### MSLDAP Functions ####
    async def get_all_schemaentry(self, attrs:List[str]):
        for attridx in self.attr_index:
            if isinstance(attridx, int) is False:
                continue

            if hasattr(self.attr_index[attridx], 'schemaIDGUID') is True:
                dn = self.attr_index[attridx].DN.upper()
                if dn not in self.dn_index:
                    logger.debug('[ADEXPLORER] DN not found in index: %s' % dn)
                    continue
                temp = {}
                temp['attributes'] = {}
                for attr in attrs:
                    res = self.dn_index[dn][attr]
                    if res is not None:
                        temp['attributes'][attr] = res
                yield MSADSchemaEntry.from_ldap(temp), None

    async def get_ad_info(self, attrs:List[str] = MSADInfo_ATTRS):
        temp = {}
        temp['attributes'] = {}
        for attr in attrs:
            temp['attributes'][attr] = self.dn_index[self.rootdomain][attr]
        return MSADInfo.from_ldap(temp), None

    async def get_all_trusts(self, attrs:List[str] = MSADDomainTrust_ATTRS):
        #(objectClass=trustedDomain)'
        for dn in self.dn_index:
            if 'trustedDomain' in self.dn_index[dn]._bhcache['objectClass']:
                temp = {}
                temp['attributes'] = {}
                for attr in attrs:
                    res = self.dn_index[dn][attr]
                    if res is not None:
                        temp['attributes'][attr] = res
                yield MSADDomainTrust.from_ldap(temp), None
    
    async def get_all_users(self, attrs:List[str] = MSADUser_ATTRS):
        for dn in self.dn_index:
            if self.dn_index[dn]._bhcache['sAMAccountType'] == 805306368:
                temp = {}
                temp['attributes'] = {}
                for attr in attrs:
                    res = self.dn_index[dn][attr]
                    if res is not None:
                        temp['attributes'][attr] = res
                yield MSADUser.from_ldap(temp), None

    async def get_all_machines(self, attrs:List[str] = MSADMachine_ATTRS):
        for dn in self.dn_index:
            if self.dn_index[dn]._bhcache['sAMAccountType'] == 805306369:
                temp = {}
                temp['attributes'] = {}
                for attr in attrs:
                    res = self.dn_index[dn][attr]
                    if res is not None:
                        temp['attributes'][attr] = res
                yield MSADMachine.from_ldap(temp), None

    async def get_all_groups(self, attrs:List[str] = MSADGroup_ATTRS):
        for dn in self.dn_index:
            if 'group' in self.dn_index[dn]._bhcache['objectClass']:
                temp = {}
                temp['attributes'] = {}
                for attr in attrs:
                    res = self.dn_index[dn][attr]
                    if res is not None:
                        temp['attributes'][attr] = res
                yield MSADGroup.from_ldap(temp), None

    async def get_all_ous(self, attrs:List[str] = MSADOU_ATTRS):
        for dn in self.dn_index:
            if 'organizationalUnit' in self.dn_index[dn]._bhcache['objectClass']:
                temp = {}
                temp['attributes'] = {}
                for attr in attrs:
                    res = self.dn_index[dn][attr]
                    if res is not None:
                        temp['attributes'][attr] = res
                yield MSADOU.from_ldap(temp), None
    
    async def get_all_gpos(self, attrs:List[str] = MSADGPO_ATTRS):
        for dn in self.dn_index:
            if 'groupPolicyContainer' in self.dn_index[dn]._bhcache['objectClass']:
                temp = {}
                temp['attributes'] = {}
                for attr in attrs:
                    res = self.dn_index[dn][attr]
                    if res is not None:
                        temp['attributes'][attr] = res
                yield MSADGPO.from_ldap(temp), None
    
    async def get_all_containers(self, attrs:List[str] = MSADContainer_ATTRS):
        for dn in self.dn_index:
            bhcache = self.dn_index[dn]._bhcache
            if 'CONTAINER' in bhcache['objectCategory'].upper() and 'container' in bhcache['objectClass']:
                temp = {}
                temp['attributes'] = {}
                for attr in attrs:
                    res = self.dn_index[dn][attr]
                    if res is not None:
                        temp['attributes'][attr] = res
                yield MSADContainer.from_ldap(temp), None

    async def get_all_foreignsecurityprincipals(self, attrs:List[str]):
        for dn in self.dn_index:
            bhcache = self.dn_index[dn]._bhcache
            if 'foreignSecurityPrincipal' in bhcache['objectClass'] and 'FOREIGN-SECURITY-PRINCIPAL' in bhcache['objectCategory'].upper():
                temp = {}
                temp['attributes'] = {}
                for attr in attrs:
                    res = self.dn_index[dn][attr]
                    if res is not None:
                        temp['attributes'][attr] = res
                yield temp, None

    async def get_objectacl_by_dn(self, dn:str):
        return self.dn_index[dn.upper()]['nTSecurityDescriptor'], None
    
    async def dnattrs(self, dn, attrs:List[str]):
        dn = dn.upper()
        if dn not in self.dn_index:
            return {}, None
        temp = {}
        temp['attributes'] = {}
        for attr in attrs:
            res = self.dn_index[dn][attr]
            if res is not None:
                temp['attributes'][attr] = res
        
        return temp['attributes'], None

async def amain():
    import traceback
    try:
        sn = await Snapshot.from_file('dd2.dat')
        i = 0
        entry = ''
        async for entry, err in sn.get_all_schemaentry(['name', 'schemaIDGUID']):
            if err is not None:
                raise err
            i += 1
        print(entry)
        print('Total schema entries: %s' % i)
        
        adinfo, err = await sn.get_ad_info()
        if err is not None:
            raise err
        
        print(adinfo)

        i = 0 
        async for entry, err in sn.get_all_trusts():
            if err is not None:
                raise err
        
        print(entry)

        i = 0
        async for entry, err in sn.get_all_users():
            if err is not None:
                raise err
            i += 1
        print(entry)
        print('Total users: %s' % i)

        i = 0
        async for entry, err in sn.get_all_machines():
            if err is not None:
                raise err
            i += 1
        print(entry)
        print('Total machines: %s' % i)
        
        i = 0
        async for entry, err in sn.get_all_groups():
            if err is not None:
                raise err
            i += 1

        print(entry)
        print('Total groups: %s' % i)

        i = 0
        async for entry, err in sn.get_all_ous():
            if err is not None:
                raise err
            i += 1

        print(entry)
        print('Total ous: %s' % i)

        i = 0
        async for entry, err in sn.get_all_gpos():
            if err is not None:
                raise err
            i += 1

        print(entry)
        print('Total gpos: %s' % i)


    except Exception as e:
        traceback.print_exc()

def main():
    import asyncio
    asyncio.run(amain())
    
if __name__ == '__main__':
    main()