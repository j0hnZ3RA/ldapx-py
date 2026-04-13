"""Tests for the high-level obfuscation API and chain execution."""

import random
import pytest

import ldapx
from ldapx.middlewares.filter import FilterMiddlewareChain, rand_case_filter_obf
from ldapx.parser import query_to_filter, filter_to_query


class TestObfuscateFilter:
    def test_basic(self):
        random.seed(42)
        result = ldapx.obfuscate_filter("(cn=admin)", "C")
        assert result != ""
        assert "=" in result

    def test_chain_co(self):
        random.seed(42)
        result = ldapx.obfuscate_filter("(cn=admin)", "CO")
        assert "oID." in result or "2.5.4.3" in result

    def test_empty_filter_passthrough(self):
        assert ldapx.obfuscate_filter("", "C") == ""

    def test_empty_chain_passthrough(self):
        assert ldapx.obfuscate_filter("(cn=admin)", "") == "(cn=admin)"

    def test_unknown_code_warns(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING):
            ldapx.obfuscate_filter("(cn=admin)", "Z9Z")


class TestObfuscateBaseDN:
    def test_basic(self):
        random.seed(42)
        result = ldapx.obfuscate_basedn("DC=corp,DC=local", "C")
        assert result != ""
        assert "=" in result

    def test_oid(self):
        random.seed(42)
        result = ldapx.obfuscate_basedn("DC=corp,DC=local", "O")
        assert "oID." in result


class TestObfuscateAttrList:
    def test_basic(self):
        random.seed(42)
        result = ldapx.obfuscate_attrlist(["cn", "sAMAccountName"], "C")
        assert len(result) == 2

    def test_reorder(self):
        random.seed(42)
        attrs = ["a", "b", "c", "d", "e"]
        result = ldapx.obfuscate_attrlist(attrs, "R")
        assert sorted(result) == sorted(attrs)


class TestObfuscateAttrEntries:
    def test_basic(self):
        random.seed(42)
        entries = {"cn": [b"test"], "sn": [b"user"]}
        result = ldapx.obfuscate_attrentries(entries, "C")
        assert len(result) == 2


class TestFilterMiddlewareChain:
    def test_chain_execution(self):
        chain = FilterMiddlewareChain()
        chain.add("Case", lambda: rand_case_filter_obf(1.0))

        f = query_to_filter("(cn=admin)")
        result = chain.execute(f)
        output = filter_to_query(result)
        # Case mutation produces valid filter
        assert output.startswith("(")
        assert "=" in output
        assert output.lower() == "(cn=admin)"


class TestOptions:
    def test_custom_options(self):
        opts = ldapx.Options(FiltCaseProb=1.0)
        result = ldapx.obfuscate_filter("(cn=admin)", "C", options=opts)
        # Case mutation produces valid filter with same semantic content
        assert result.lower() == "(cn=admin)"

    def test_defaults(self):
        opts = ldapx.Options.defaults()
        assert opts.get("FiltCaseProb") == 0.5

    def test_zero_filter_limits_do_not_crash(self):
        opts = ldapx.Options(
            FiltGarbageMaxElems=0,
            FiltBoolMaxDepth=0,
            FiltDblNegMaxDepth=0,
            FiltSpacingMaxSpaces=0,
            FiltPrependZerosMax=0,
            FiltANRGarbageMaxChars=0,
        )
        result = ldapx.obfuscate_filter("(cn=admin)", "GBDSZn", options=opts)
        assert result.startswith("(")
        assert "=" in result
        result_num = ldapx.obfuscate_filter("(userAccountControl=512)", "Z", options=opts)
        assert result_num == "(userAccountControl=512)"

    def test_zero_attrlist_limits_do_not_crash(self):
        opts = ldapx.Options(
            AttrsGarbageMaxElems=0,
            AttrsExistingGarbageMax=0,
        )
        result = ldapx.obfuscate_attrlist(["cn", "sn"], "Gg", options=opts)
        assert result == ["cn", "sn"]

    def test_literal_escaped_asterisk_is_preserved(self):
        opts = ldapx.Options(FiltCaseProb=0)
        result = ldapx.obfuscate_filter(r"(cn=rob\2astark)", "C", options=opts)
        assert result == r"(cn=rob\2astark)"
