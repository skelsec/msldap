from __future__ import annotations

from typing import List, Optional

from msldap.commons.utils import bytes2ipv4, bytes2ipv6


# NOTE: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/588ae296-71bf-402f-9996-86ecee39dc29
class Ip4Array:
    def __init__(self, servers: List[str] = []) -> Ip4Array:
        self._servers = servers.copy()

    @classmethod
    def from_bytes(cls, data: bytes, _: Optional[str] = None) -> Ip4Array:
        num_ips = int.from_bytes(data[:4], "little")

        ips = [bytes2ipv4(data[i * 4 + 4 : i * 4 + 8]) for i in range(num_ips)]

        return Ip4Array(ips)

    def __str__(self) -> str:
        if self._servers == []:
            return "None"

        return ", ".join(self._servers)


# NOTE: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/56ba5fab-f304-4866-99a4-4f1c1f9247a3
class DnsAddrArray:
    AF_IPV4 = 0x0002
    AF_IPV6 = 0x0017

    def __init__(self, servers: List[str] = []) -> DnsAddrArray:
        self._servers = servers.copy()

    @classmethod
    def from_bytes(cls, data: bytes, _: Optional[str] = None) -> DnsAddrArray:
        num_addrs = int.from_bytes(data[:4], "little")

        servers = list()

        for i in range(num_addrs):
            raw_addr = data[32 + i * 64 : 32 + (i + 1) * 64]

            family = int.from_bytes(raw_addr[:2], "little")
            if family == cls.AF_IPV4:
                ip = bytes2ipv4(raw_addr[4:8])
            elif family == cls.AF_IPV6:
                ip = bytes2ipv6(raw_addr[8:24])
            else:
                ip = "Unknown"

            port = int.from_bytes(raw_addr[2:4], "big")

            servers.append(f"{ip}:{port}")

        return DnsAddrArray(servers)

    def __str__(self) -> str:
        if self._servers == []:
            return "None"

        return ", ".join(self._servers)
