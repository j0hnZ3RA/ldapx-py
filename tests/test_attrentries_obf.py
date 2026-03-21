"""Tests for AttrEntries obfuscation middlewares."""

import random
import pytest

from ldapx.middlewares.attrentries import (
    rand_case_attrentries_obf,
    oid_attribute_attrentries_obf,
    reorder_list_attrentries_obf,
)


class TestRandCaseAttrEntries:
    def test_preserves_values(self):
        random.seed(42)
        entries = {"cn": [b"test"], "sn": [b"user"]}
        result = rand_case_attrentries_obf(1.0)(entries)
        assert len(result) == 2
        # Values should be preserved
        values = list(result.values())
        assert [b"test"] in values
        assert [b"user"] in values

    def test_keys_case_changed(self):
        random.seed(42)
        entries = {"cn": [b"test"]}
        result = rand_case_attrentries_obf(1.0)(entries)
        key = list(result.keys())[0]
        assert key.lower() == "cn"

    def test_no_mutation(self):
        entries = {"cn": [b"test"]}
        result = rand_case_attrentries_obf(0.0)(entries)
        assert "cn" in result


class TestOIDAttributeAttrEntries:
    def test_replaces_known_attrs(self):
        entries = {"cn": [b"test"], "sn": [b"user"]}
        result = oid_attribute_attrentries_obf()(entries)
        keys = list(result.keys())
        # cn OID is 2.5.4.3, sn OID is 2.5.4.4
        assert "2.5.4.3" in keys
        assert "2.5.4.4" in keys

    def test_preserves_unknown(self):
        entries = {"nonExistent123": [b"val"]}
        result = oid_attribute_attrentries_obf()(entries)
        assert "nonExistent123" in result

    def test_preserves_values(self):
        entries = {"cn": [b"test"]}
        result = oid_attribute_attrentries_obf()(entries)
        assert list(result.values()) == [[b"test"]]


class TestReorderAttrEntries:
    def test_preserves_all_items(self):
        random.seed(42)
        entries = {"cn": [b"a"], "sn": [b"b"], "mail": [b"c"]}
        result = reorder_list_attrentries_obf()(entries)
        assert len(result) == 3
        assert set(result.keys()) == {"cn", "sn", "mail"}
        assert result["cn"] == [b"a"]
        assert result["sn"] == [b"b"]
        assert result["mail"] == [b"c"]


class TestAttrEntriesChaining:
    def test_case_then_reorder(self):
        random.seed(42)
        entries = {"cn": [b"a"], "sn": [b"b"], "description": [b"c"]}
        result = rand_case_attrentries_obf(0.5)(entries)
        result = reorder_list_attrentries_obf()(result)
        assert len(result) == 3
        # Values preserved
        all_values = list(result.values())
        assert [b"a"] in all_values
        assert [b"b"] in all_values
        assert [b"c"] in all_values
