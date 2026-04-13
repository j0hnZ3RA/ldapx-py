"""Tests for AttrList obfuscation middlewares."""

import random
import pytest

from ldapx.middlewares.attrlist import (
    rand_case_attrlist_obf,
    oid_attribute_attrlist_obf,
    duplicate_attrlist_obf,
    garbage_existing_attrlist_obf,
    garbage_non_existing_attrlist_obf,
    add_wildcard_attrlist_obf,
    add_plus_attrlist_obf,
    replace_with_wildcard_attrlist_obf,
    replace_with_empty_attrlist_obf,
    reorder_list_attrlist_obf,
)


class TestRandCaseAttrList:
    def test_preserves_count(self):
        result = rand_case_attrlist_obf(1.0)(["cn", "sn", "mail"])
        assert len(result) == 3

    def test_preserves_content(self):
        random.seed(42)
        result = rand_case_attrlist_obf(1.0)(["cn", "sn"])
        assert [r.lower() for r in result] == ["cn", "sn"]

    def test_no_mutation(self):
        result = rand_case_attrlist_obf(0.0)(["cn", "sn"])
        assert result == ["cn", "sn"]


class TestOIDAttributeAttrList:
    def test_replaces_known_attrs(self):
        random.seed(42)
        result = oid_attribute_attrlist_obf(0, 0)(["cn", "sn"])
        assert all("oID." in r for r in result)

    def test_preserves_unknown_attrs(self):
        random.seed(42)
        result = oid_attribute_attrlist_obf(0, 0)(["nonExistentAttr123"])
        assert result == ["nonExistentAttr123"]

    def test_without_prefix(self):
        result = oid_attribute_attrlist_obf(0, 0, include_prefix=False)(["cn"])
        assert result == ["2.5.4.3"]


class TestDuplicateAttrList:
    def test_adds_duplicates(self):
        random.seed(42)
        attrs = ["cn", "sn", "mail"]
        result = duplicate_attrlist_obf(1.0)(attrs)
        assert len(result) > len(attrs)

    def test_at_least_one_dup(self):
        attrs = ["cn", "sn"]
        result = duplicate_attrlist_obf(0.0)(attrs)
        # Even with prob=0, at least one dup is added if none happened
        assert len(result) > len(attrs)


class TestGarbageAttrList:
    def test_existing_garbage(self):
        random.seed(42)
        attrs = ["cn"]
        result = garbage_existing_attrlist_obf(2)(attrs)
        assert len(result) > 1
        assert "cn" in result

    def test_non_existing_garbage(self):
        random.seed(42)
        attrs = ["cn"]
        result = garbage_non_existing_attrlist_obf(2, 10)(attrs)
        assert len(result) > 1
        assert "cn" in result

    def test_empty_attrs_passthrough(self):
        result = garbage_existing_attrlist_obf(2)([])
        assert result == []


class TestWildcardAttrList:
    def test_add_wildcard(self):
        result = add_wildcard_attrlist_obf()(["cn", "sn"])
        assert "*" in result
        assert "cn" in result
        assert "sn" in result

    def test_add_plus(self):
        result = add_plus_attrlist_obf()(["cn"])
        assert "+" in result
        assert "cn" in result

    def test_add_plus_empty(self):
        result = add_plus_attrlist_obf()([])
        assert "*" in result
        assert "+" in result

    def test_replace_with_wildcard(self):
        result = replace_with_wildcard_attrlist_obf()(["cn", "sn", "+"])
        assert "*" in result
        assert "+" in result
        assert "cn" not in result

    def test_replace_with_empty(self):
        result = replace_with_empty_attrlist_obf()(["cn", "sn"])
        # No operational attrs → empty
        assert result == []

    def test_replace_with_empty_preserves_operational(self):
        result = replace_with_empty_attrlist_obf()(["cn", "createtimestamp"])
        assert "createtimestamp" in result
        assert "*" in result


class TestReorderAttrList:
    def test_preserves_elements(self):
        random.seed(42)
        attrs = ["a", "b", "c", "d", "e"]
        result = reorder_list_attrlist_obf()(attrs)
        assert sorted(result) == sorted(attrs)

    def test_preserves_count(self):
        attrs = ["cn", "sn", "mail"]
        result = reorder_list_attrlist_obf()(attrs)
        assert len(result) == 3
