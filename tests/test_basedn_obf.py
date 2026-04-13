"""Tests for BaseDN obfuscation middlewares."""

import random
import pytest

from ldapx.middlewares.basedn import (
    rand_case_basedn_obf,
    oid_attribute_basedn_obf,
    rand_spacing_basedn_obf,
    double_quotes_basedn_obf,
    guid_basedn_obf,
    sid_basedn_obf,
    wkguid_basedn_obf,
    rand_hex_value_basedn_obf,
)


class TestRandCaseBaseDN:
    def test_preserves_content(self):
        random.seed(42)
        result = rand_case_basedn_obf(1.0)("DC=corp,DC=local")
        assert result.lower() == "dc=corp,dc=local"

    def test_no_mutation(self):
        result = rand_case_basedn_obf(0.0)("DC=corp,DC=local")
        assert result == "DC=corp,DC=local"


class TestOIDAttributeBaseDN:
    def test_replaces_with_oid(self):
        random.seed(42)
        result = oid_attribute_basedn_obf(0, 0)("DC=corp,DC=local")
        assert "oID." in result

    def test_adds_spaces(self):
        random.seed(42)
        result = oid_attribute_basedn_obf(3, 0)("DC=corp")
        assert " " in result

    def test_adds_zeros(self):
        random.seed(42)
        result = oid_attribute_basedn_obf(0, 3)("DC=corp")
        assert "0" in result

    def test_preserves_values(self):
        random.seed(42)
        result = oid_attribute_basedn_obf(0, 0)("DC=corp,DC=local")
        assert "corp" in result
        assert "local" in result

    def test_without_prefix(self):
        result = oid_attribute_basedn_obf(0, 0, include_prefix=False)("DC=corp")
        assert result == "0.9.2342.19200300.100.1.25=corp"


class TestRandSpacingBaseDN:
    def test_adds_spaces(self):
        random.seed(42)
        result = rand_spacing_basedn_obf(3)("DC=corp,DC=local")
        assert len(result) > len("DC=corp,DC=local")
        assert " " in result

    def test_empty_dn(self):
        result = rand_spacing_basedn_obf(3)("")
        assert result == ""

    def test_zero_spaces(self):
        result = rand_spacing_basedn_obf(0)("DC=corp")
        assert result == "DC=corp"

    def test_skips_alternative_form(self):
        result = rand_spacing_basedn_obf(3)("<GUID=0123456789abcdef0123456789abcdef>")
        assert result == "<GUID=0123456789abcdef0123456789abcdef>"


class TestDoubleQuotesBaseDN:
    def test_adds_quotes(self):
        result = double_quotes_basedn_obf()("DC=corp,DC=local")
        assert '"' in result
        assert '"corp"' in result or '"local"' in result

    def test_skips_escaped_values(self):
        result = double_quotes_basedn_obf()("CN=test\\,value,DC=corp")
        # Should skip the escaped value
        assert result.count('"') >= 2  # at least DC=corp gets quotes

    def test_skips_alternative_form(self):
        result = double_quotes_basedn_obf()("<GUID=0123456789abcdef0123456789abcdef>")
        assert result == "<GUID=0123456789abcdef0123456789abcdef>"


class TestRandHexValueBaseDN:
    def test_hex_encodes(self):
        random.seed(42)
        result = rand_hex_value_basedn_obf(1.0)("DC=corp,DC=local")
        assert "\\" in result

    def test_no_encoding(self):
        result = rand_hex_value_basedn_obf(0.0)("DC=corp,DC=local")
        assert result == "DC=corp,DC=local"

    def test_skips_quoted_values(self):
        result = rand_hex_value_basedn_obf(1.0)('DC="corp",DC=local')
        # Quoted value should be skipped
        assert '"corp"' in result

    def test_skips_alternative_form(self):
        result = rand_hex_value_basedn_obf(1.0)("<GUID=0123456789abcdef0123456789abcdef>")
        assert result == "<GUID=0123456789abcdef0123456789abcdef>"


class TestAlternativeForms:
    def test_case_skips_alternative_form(self):
        result = rand_case_basedn_obf(1.0)("<GUID=0123456789abcdef0123456789abcdef>")
        assert result == "<GUID=0123456789abcdef0123456789abcdef>"

    def test_oid_skips_alternative_form(self):
        result = oid_attribute_basedn_obf(2, 2)("<GUID=0123456789abcdef0123456789abcdef>")
        assert result == "<GUID=0123456789abcdef0123456789abcdef>"

    def test_sid_bytes_are_normalized(self):
        sid_bytes = b"\x01\x01\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00"
        result = sid_basedn_obf(sid_bytes)("DC=corp,DC=local")
        assert result == "<SID=S-1-5-32>"

    def test_wkguid_for_known_container(self):
        result = wkguid_basedn_obf()("CN=Users,DC=corp,DC=local")
        assert result.startswith("<WKGUID=")
        assert result.endswith(",DC=corp,DC=local>")

    def test_wkguid_passthrough_for_domain_root(self):
        result = wkguid_basedn_obf()("DC=corp,DC=local")
        assert result == "DC=corp,DC=local"


class TestBaseDNChaining:
    def test_multiple_middlewares(self):
        random.seed(42)
        dn = "DC=corp,DC=local"
        dn = rand_case_basedn_obf(0.5)(dn)
        dn = oid_attribute_basedn_obf(2, 2)(dn)
        dn = double_quotes_basedn_obf()(dn)
        assert "oID." in dn
        assert '"' in dn
