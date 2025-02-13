# NOTE: implementation is based on https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/445c7843-e4a1-4222-8c0f-630c230a4c80

from __future__ import annotations

import sys
from typing import ClassVar, Generic, List, Optional, TypeVar

from msldap.commons.utils import timestamp2datetime
from msldap.wintypes.dnsp.structures.misc import DnsAddrArray, Ip4Array

# NOTE: typing.Type is deprecated since version 3.9
if sys.version_info < (3, 9):
    from typing import Type
else:
    Type = type


# NOTE: to make typing happy with auto-implementation of from_bytes
class _Unserializable:
    @classmethod
    def from_bytes(cls, data: bytes, byteorder: str) -> _Unserializable:
        ...


# NOTE: by default, consider BaseType unserializable to make possible the generation of from_bytes method
BaseType = TypeVar("BaseType", bound=_Unserializable)


class BaseDnsProperty(Generic[BaseType]):
    _id: ClassVar[int] = None
    _name: ClassVar[str] = None

    _base_type: ClassVar[Type[BaseType]] = None
    _default: ClassVar[BaseType] = None

    _implementations: ClassVar[List[Type[BaseDnsProperty]]] = []

    def __init__(self, value: Optional[BaseType] = None) -> None:
        self._value = value if value is not None else self._default

    def __str__(self) -> str:
        return f"{self._name}: {self.value}"

    @property
    def value(self) -> str:
        return str(self._value)

    @classmethod
    def from_bytes(cls, data: bytes) -> BaseDnsProperty:
        return cls(cls._base_type.from_bytes(data, "little"))

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)

        cls._base_type = cls.__orig_bases__[0].__args__[0]

        if (cls._id is not None) and (cls._name is not None):
            cls._implementations.append(cls)


class DnsEnumProperty(BaseDnsProperty[int]):
    _types: ClassVar[dict[int, str]] = None

    @property
    def value(self) -> str:
        return self._types.get(self._value, "Unknown")


class DnsFlagsProperty(BaseDnsProperty[int]):
    _flags: ClassVar[dict[int, str]] = None

    @property
    def value(self) -> str:
        return " | ".join(
            value for (key, value) in self._flags.items() if (self._value & key)
        )


class DnsHoursIntervalProperty(BaseDnsProperty[int]):
    @property
    def value(self) -> str:
        if self._value == 0:
            return "0 hours"

        result = ""

        days = self._value // 24
        if days != 0:
            result += f"{days} days "

        hours = self._value % 24
        if hours != 0:
            result += f"{hours} hours "

        return result.rstrip()


class DnsTimestampProperty(BaseDnsProperty[int]):
    @property
    def value(self) -> str:
        if self._value == 0:
            return "Never"

        return timestamp2datetime(self._value).isoformat()


class DnsNullTerminatedStringProperty(BaseDnsProperty[str]):
    @classmethod
    def from_bytes(cls, data: bytes) -> DnsNullTerminatedStringProperty:
        return cls(data.decode("utf-8").rstrip("\x00"))


# NOTE: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/27e138a7-110c-44a4-afcb-b95f35f00306
class DnsZoneType(DnsEnumProperty):
    _id = 0x01
    _name = "Zone Type"

    _default = 1

    _types = {
        0: "Cache",
        1: "Primary",
        2: "Secondary",
        3: "Stub",
        4: "Forwarder",
        5: "Secondary Cache",
    }


# NOTE: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d4b84209-f00c-478f-80d7-8dd0f1633d9e
class DnsZoneAllowUpdate(DnsEnumProperty):
    _id = 0x02
    _name = "Dynamic Updates"

    _default = -1

    _types = {
        0: "Not allowed",
        1: "All updates allowed",
        2: "Only secure updates allowed",
    }


class DnsZoneSecureTime(DnsTimestampProperty):
    _id = 0x08
    _name = "Time Zone Secured"

    _default = 0


class DnsZoneNoRefreshInterval(DnsHoursIntervalProperty):
    _id = 0x10
    _name = "Zone No-Refresh Interval"

    _default = 168


class DnsZoneRefreshInterval(DnsHoursIntervalProperty):
    _id = 0x20
    _name = "Zone Refresh Interval"

    _default = 168


class DnsZoneAgingState(BaseDnsProperty[bool]):
    _id = 0x40
    _name = "Aging Enabled"

    _default = False


class DnsZoneScavengingServers(BaseDnsProperty[Ip4Array]):
    _id = 0x11
    _name = "DNS Servers performing Scavenging"

    _default = Ip4Array()


class DnsZoneAgingEnabledTime(DnsHoursIntervalProperty):
    _id = 0x12
    _name = "Time before the next Scavenging Cycle"

    _default = 0


class DnsZoneDeletedFromHostname(DnsNullTerminatedStringProperty):
    _id = 0x80
    _name = "Name of Server that deleted the Zone"

    _default = "Unknown"


class DnsZoneMasterServers(BaseDnsProperty[Ip4Array]):
    _id = 0x81
    _name = "DNS Servers performing Zone Transfers"

    _default = Ip4Array()


class DnsZoneAutoNsServers(BaseDnsProperty[Ip4Array]):
    _id = 0x82
    _name = "DNS Servers which may autocreate a Delegation"

    _default = Ip4Array()


# NOTE: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/4ec7bdf7-1807-4179-96af-ce1c1cd448b7
class DnsZoneDcPromoConvert(DnsEnumProperty):
    _id = 0x83
    _name = "State of Conversion"

    _default = 0

    _types = {
        0: "None",
        1: "To be moved to DNS Domain partition",
        2: "To be moved to DNS Forest partition",
    }


class DnsZoneScavengingServersDa(BaseDnsProperty[DnsAddrArray]):
    _id = 0x90
    _name = "DNS Servers performing Scavenging"

    _default = DnsAddrArray()


class DnsZoneMasterServersDa(BaseDnsProperty[DnsAddrArray]):
    _id = 0x91
    _name = "DNS Servers performing Zone Transfers"

    _default = DnsAddrArray()


class DnsZoneAutoNsServersDa(BaseDnsProperty[DnsAddrArray]):
    _id = 0x92
    _name = "DNS Servers which may autocreate a Delegation"

    _default = DnsAddrArray()


# NOTE: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f448341f-512d-414a-aaa3-e303d592fcd2
class DnsZoneNodeDbFlags(DnsFlagsProperty):
    _id = 0x100
    _name = "DB Flags"

    _default = 0

    _flags = {
        0x80000000: "DNS_RPC_FLAG_CACHE_DATA",
        0x40000000: "DNS_RPC_FLAG_ZONE_ROOT",
        0x20000000: "DNS_RPC_FLAG_AUTH_ZONE_ROOT",
        0x10000000: "DNS_RPC_FLAG_ZONE_DELEGATION",
        0x08000000: "DNS_RPC_FLAG_RECORD_DEFAULT_TTL",
        0x04000000: "DNS_RPC_FLAG_RECORD_TTL_CHANGE",
        0x02000000: "DNS_RPC_FLAG_RECORD_CREATE_PTR",
        0x01000000: "DNS_RPC_FLAG_NODE_STICKY",
        0x00800000: "DNS_RPC_FLAG_NODE_COMPLETE",
        0x00010000: "DNS_RPC_FLAG_SUPPRESS_NOTIFY",
        0x00020000: "DNS_RPC_FLAG_AGING_ON",
        0x00040000: "DNS_RPC_FLAG_OPEN_ACL",
        0x00100000: "DNS_RPC_FLAG_RECORD_WIRE_FORMAT",
        0x00200000: "DNS_RPC_FLAG_SUPPRESS_RECORD_UPDATE_PTR",
    }


class DnsPropertyFactory:
    def __init__(self) -> None:
        self._factories = {
            subclass._id: subclass for subclass in BaseDnsProperty._implementations
        }

    def from_bytes(self, data: bytes) -> Optional[BaseDnsProperty]:
        length = int.from_bytes(data[:4], "little")
        id = int.from_bytes(data[16:20], "little")

        FactoryClass = self._factories.get(id)
        if FactoryClass is None:
            return None

        if length == 0:
            return FactoryClass()

        return FactoryClass.from_bytes(data[20 : 20 + length])
