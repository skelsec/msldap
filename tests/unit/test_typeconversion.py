"""Offline tests for msldap.protocol.typeconversion."""
import datetime

import pytest
from winacl.dtyp.sid import SID

from msldap.protocol import typeconversion as tc
from support.builders import make_raw_attributes

pytestmark = pytest.mark.unit


class TestSingleValueDecoders:
    def test_single_str(self):
        assert tc.single_str([b"hello"]) == "hello"

    def test_single_int(self):
        assert tc.single_int([b"42"]) == 42

    def test_single_bool_true(self):
        assert tc.single_bool([b"TRUE"]) is True

    def test_single_bool_false(self):
        assert tc.single_bool([b"FALSE"]) is False

    def test_single_bool_treats_unknown_as_true(self):
        # documents current (permissive) behavior: anything != 'FALSE' -> True
        assert tc.single_bool([b"garbage"]) is True

    def test_single_bytes(self):
        assert tc.single_bytes([b"\x00\x01"]) == b"\x00\x01"

    def test_single_sid(self):
        sid = "S-1-5-21-1-2-3-500"
        assert tc.single_sid([SID.from_string(sid).to_bytes()]) == sid

    def test_single_utf16le(self):
        assert tc.single_utf16le(["password".encode("utf-16-le")]) == "password"

    def test_single_interval_max(self):
        # 0x7FFFFFFFFFFFFFFF is the 'never' sentinel
        result = tc.single_interval([9223372036854775807])
        assert result == datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)

    def test_single_interval_epoch(self):
        # value of 0 -> the FILETIME epoch (1601-01-01)
        result = tc.single_interval([0])
        assert result.year == 1601


    def test_int2timedelta_never_sentinel(self):
        # -2**63 is the '(never)' sentinel and maps to timedelta.max
        assert tc.int2timedelta([-9223372036854775808]) == datetime.timedelta.max


class TestSingleValueEncoders:
    def test_single_str_encode(self):
        assert tc.single_str("hello", True) == [b"hello"]

    def test_single_int_encode(self):
        assert tc.single_int(42, True) == [b"42"]

    def test_single_bool_encode(self):
        assert tc.single_bool(True, True) == [b"TRUE"]
        assert tc.single_bool(False, True) == [b"FALSE"]

    def test_single_sid_roundtrip(self):
        sid = "S-1-5-21-9-8-7-1000"
        encoded = tc.single_sid(sid, True)
        assert tc.single_sid(encoded) == sid


class TestMultiValue:
    def test_multi_str(self):
        assert tc.multi_str([b"a", b"b"]) == ["a", "b"]

    def test_multi_int(self):
        assert tc.multi_int([b"1", b"2", b"3"]) == [1, 2, 3]

    def test_multi_str_roundtrip(self):
        assert tc.multi_str(tc.multi_str(["x", "y"], True)) == ["x", "y"]

    def test_multi_sid(self):
        sids = ["S-1-5-32-544", "S-1-1-0"]
        raw = [SID.from_string(s).to_bytes() for s in sids]
        assert tc.multi_sid(raw) == sids

    def test_multi_sd_decode(self):
        # a minimal self-relative SD blob; one decoded SD per input element
        blank_sd = b"\x01\x00\x04\x80\x14\x00\x00\x00\x24\x00\x00\x00\x00\x00\x00\x00\x30\x00\x00\x00"
        assert len(tc.multi_sd([blank_sd])) == 1
        assert len(tc.multi_sd([blank_sd, blank_sd])) == 2


class TestConvertAttributes:
    def test_mixed_types(self):
        raw = make_raw_attributes(
            {
                "sAMAccountName": [b"admin"],
                "objectClass": [b"top", b"person"],
                "badPwdCount": [b"3"],
            }
        )
        result = tc.convert_attributes(raw)
        assert result["sAMAccountName"] == "admin"
        assert result["objectClass"] == ["top", "person"]
        assert result["badPwdCount"] == 3

    def test_unknown_attribute_left_raw(self):
        raw = make_raw_attributes({"totallyUnknownAttr": [b"\x00\x01"]})
        result = tc.convert_attributes(raw)
        assert result["totallyUnknownAttr"] == [b"\x00\x01"]

    def test_convert_result_shape(self):
        entry = {
            "objectName": b"CN=admin,DC=test,DC=corp",
            "attributes": make_raw_attributes({"sAMAccountName": [b"admin"]}),
        }
        result = tc.convert_result(entry)
        assert result["objectName"] == "CN=admin,DC=test,DC=corp"
        assert result["attributes"]["sAMAccountName"] == "admin"


class TestEncodeAttributes:
    def test_encode_known_attributes(self):
        encoded = tc.encode_attributes({"sAMAccountName": "admin", "description": "d"})
        assert len(encoded) == 2

    def test_encode_unknown_raises(self):
        with pytest.raises(Exception):
            tc.encode_attributes({"totallyUnknownAttr": "x"})


class TestEncodeChanges:
    def test_encode_changes_known_attr(self):
        # value shape: {attr: [(operation, value), ...]}
        changes = tc.encode_changes({"description": [(2, "newdesc")]})
        assert len(changes) == 1

    def test_encode_changes_unknown_raises(self):
        with pytest.raises(Exception):
            tc.encode_changes({"totallyUnknownAttr": [(2, "x")]})
