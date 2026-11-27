"""Offline tests for the ``dnsqueryall`` console command.

``do_dnsqueryall`` used to call ``connection.dns_query(None, ...)``. ``dns_query``
builds a filter with ``escape_filter_chars(target)``, which does
``text.replace(...)`` on its argument, so passing ``None`` raised

    AttributeError: 'NoneType' object has no attribute 'replace'

and every invocation failed before a single record was read (skelsec/msldap#69,
reported through bloodyAD#106). The enumerating variant is ``dns_queryall``,
which takes no target and yields records one at a time.

The connection is faked here so the tests stay offline.
"""
import asyncio

import pytest

from msldap.examples.msldapclient import MSLDAPClientConsole
from msldap.protocol.query import escape_filter_chars

pytestmark = pytest.mark.unit


class FakeConnection:
    """Minimal stand-in exposing only ``dns_queryall``."""

    def __init__(self, records, tree="DC=example,DC=local", error=None):
        self.records = records
        self.tree = tree
        self.error = error
        self.query_all_calls = []
        self.query_calls = []

    async def dns_queryall(self, zone=None, forest=False, legacy=False, throw=True):
        self.query_all_calls.append((zone, forest, legacy))
        for record in self.records:
            yield record, self.tree, None
        # dns_queryall always terminates with a (None, tree, None) sentinel
        yield None, self.tree, self.error

    async def dns_query(self, target, zone=None, forest=False, legacy=False):
        # Mirrors the real dns_query, which builds its filter with
        # escape_filter_chars(target). Passing None therefore raises
        # AttributeError from str.replace, exactly as the issue reports.
        self.query_calls.append(target)
        escape_filter_chars(target)
        return None, self.tree, None


def _console(connection):
    console = MSLDAPClientConsole.__new__(MSLDAPClientConsole)
    console.connection = connection
    return console


def _record(name):
    return {"attributes": {"dnsRecord": [], "name": [name]}}


class TestDnsQueryAll:
    def test_collects_every_record(self, capsys):
        records = [_record("a"), _record("b"), _record("c")]
        conn = FakeConnection(records)
        console = _console(conn)

        assert asyncio.run(console.do_dnsqueryall(zone="example.local")) is True

        assert conn.query_calls == [], "dnsqueryall must not call dns_query"
        assert conn.query_all_calls == [("example.local", False, False)]
        out = capsys.readouterr().out
        assert "Tree: DC=example,DC=local" in out
        assert "Record not found!" not in out

    def test_no_attribute_error_in_traceback(self, capsys):
        # do_dnsqueryall wraps everything in a bare `except:`, which prints the
        # traceback and returns False instead of letting the exception escape.
        # So the guard has to inspect the output rather than expect a raise.
        conn = FakeConnection([_record("a")])
        console = _console(conn)

        assert asyncio.run(console.do_dnsqueryall()) is True
        captured = capsys.readouterr()
        assert "AttributeError" not in captured.err + captured.out
        assert "'NoneType' object has no attribute" not in captured.err + captured.out

    def test_empty_result_reports_not_found(self, capsys):
        conn = FakeConnection([])
        console = _console(conn)

        assert asyncio.run(console.do_dnsqueryall()) is True
        assert "Record not found!" in capsys.readouterr().out

    def test_error_from_last_page_is_raised(self, capsys):
        conn = FakeConnection([_record("a")], error=RuntimeError("boom"))
        console = _console(conn)

        # The command catches everything and returns False, printing the trace.
        assert asyncio.run(console.do_dnsqueryall()) is False
        assert "boom" in capsys.readouterr().err
