import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Union


def timestamp2datetime(dt: Union[bytes, int]) -> datetime.datetime:
    """
    Converting Windows timestamps to datetime.datetime format
    :param dt: Windows timestamp as array of bytes or integer
    :type dt: bytearray | int
    :return: datetime.datetime
    """

    if isinstance(dt, bytes):
        dt = int.from_bytes(dt, "little")

    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=dt / 10)


def datetime2timestamp(dt) -> int:
    delta = dt - datetime.datetime(1601, 1, 1)
    ns = int((delta / datetime.timedelta(microseconds=1)) * 10)
    return ns.to_bytes(8, "little", signed=False)


def bytes2ipv4(data: bytes) -> str:
    return str(IPv4Address(data))


def bytes2ipv6(data: bytes) -> str:
    return str(IPv6Address(data))


def wrap(s, w) -> str:
    return [s[i : i + w] for i in range(0, len(s), w)]


def print_cert(cert, offset=0) -> str:
    cert = cert["tbs_certificate"]
    blanks = " " * offset
    msg = [
        "Cert Subject: %s" % cert["subject"]["common_name"],
        "Cert Serial: %s" % cert["serial_number"],
        "Cert Start: %s" % cert["validity"]["not_before"],
        "Cert End: %s" % cert["validity"]["not_after"],
        "Cert Issuer: %s" % cert["issuer"]["common_name"],
    ]
    return "{}{}".format(blanks, "\n{}".format(blanks).join(msg))


def win_timestamp_to_unix(seconds):
    """
    Convert Windows timestamp (100 ns since 1 Jan 1601) to
    unix timestamp.
    """
    seconds = int(seconds)
    if seconds == 0:
        return 0
    return int((seconds - 116444736000000000) / 10000000)


def bh_dt_convert(dt: datetime.datetime):
    if dt is None or dt == 0 or dt == "0" or dt == "":
        return -1
    ts = max(0, int(dt.timestamp()))
    return ts


FUNCTIONAL_LEVELS = {
    0: "2000 Mixed/Native",
    1: "2003 Interim",
    2: "2003",
    3: "2008",
    4: "2008 R2",
    5: "2012",
    6: "2012 R2",
    7: "2016",
}

KNOWN_SIDS = {
    "S-1-0": "Null Authority",
    "S-1-0-0": "Nobody",
    "S-1-1": "World Authority",
    "S-1-1-0": "Everyone",
    "S-1-2": "Local Authority",
    "S-1-2-0": "Local",
    "S-1-3": "Creator Authority",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-4": "Owner Rights",
    "S-1-4": "Non-unique Authority",
    "S-1-5": "NT Authority",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-5-X-Y": "Logon Session",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority Local Service",
    "S-1-5-20": "NT Authority Network Service",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-32-582": "Storage Replica Administrators",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authentication",
    "S-1-5-80": "NT Service",
}
