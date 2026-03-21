"""Tests for the LDAP filter parser."""

import pytest
from ldapx.parser import (
    query_to_filter, filter_to_query,
    FilterAnd, FilterOr, FilterNot,
    FilterEqualityMatch, FilterPresent, FilterSubstring,
    FilterGreaterOrEqual, FilterLessOrEqual,
    FilterApproxMatch, FilterExtensibleMatch,
)


class TestQueryToFilter:
    def test_equality(self):
        f = query_to_filter("(cn=admin)")
        assert isinstance(f, FilterEqualityMatch)
        assert f.attribute_desc == "cn"
        assert f.assertion_value == "admin"

    def test_present(self):
        f = query_to_filter("(objectClass=*)")
        assert isinstance(f, FilterPresent)
        assert f.attribute_desc == "objectClass"

    def test_substring(self):
        f = query_to_filter("(cn=a*b*c)")
        assert isinstance(f, FilterSubstring)
        assert f.attribute_desc == "cn"
        assert len(f.substrings) == 3

    def test_greater_or_equal(self):
        f = query_to_filter("(age>=18)")
        assert isinstance(f, FilterGreaterOrEqual)
        assert f.attribute_desc == "age"
        assert f.assertion_value == "18"

    def test_less_or_equal(self):
        f = query_to_filter("(age<=65)")
        assert isinstance(f, FilterLessOrEqual)

    def test_approx_match(self):
        f = query_to_filter("(cn~=admin)")
        assert isinstance(f, FilterApproxMatch)

    def test_extensible_match(self):
        f = query_to_filter("(cn:1.2.3.4:=admin)")
        assert isinstance(f, FilterExtensibleMatch)
        assert f.attribute_desc == "cn"
        assert f.matching_rule == "1.2.3.4"
        assert f.match_value == "admin"

    def test_extensible_dn(self):
        f = query_to_filter("(cn:dn:1.2.3.4:=admin)")
        assert isinstance(f, FilterExtensibleMatch)
        assert f.dn_attributes is True

    def test_and(self):
        f = query_to_filter("(&(cn=a)(sn=b))")
        assert isinstance(f, FilterAnd)
        assert len(f.filters) == 2

    def test_or(self):
        f = query_to_filter("(|(cn=a)(sn=b))")
        assert isinstance(f, FilterOr)
        assert len(f.filters) == 2

    def test_not(self):
        f = query_to_filter("(!(cn=a))")
        assert isinstance(f, FilterNot)
        assert isinstance(f.filter, FilterEqualityMatch)

    def test_nested(self):
        f = query_to_filter("(&(|(cn=a)(sn=b))(!(objectClass=computer)))")
        assert isinstance(f, FilterAnd)
        assert len(f.filters) == 2
        assert isinstance(f.filters[0], FilterOr)
        assert isinstance(f.filters[1], FilterNot)

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            query_to_filter("")

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError):
            query_to_filter("cn=admin")


class TestRoundTrip:
    @pytest.mark.parametrize("query", [
        "(cn=admin)",
        "(objectClass=*)",
        "(cn=a*b*c)",
        "(age>=18)",
        "(age<=65)",
        "(cn~=admin)",
        "(&(cn=a)(sn=b))",
        "(|(cn=a)(sn=b))",
        "(!(cn=a))",
        "(&(|(cn=a)(sn=b))(!(objectClass=computer)))",
    ])
    def test_round_trip(self, query):
        f = query_to_filter(query)
        result = filter_to_query(f)
        assert result == query


class TestValidation:
    def test_is_oid(self):
        from ldapx.parser.validation import is_oid
        assert is_oid("1.2.3.4") is True
        assert is_oid("OID.1.2.3.4") is True
        assert is_oid("oid.1.2.3.4") is True
        assert is_oid("cn") is False
        assert is_oid("") is False

    def test_get_attribute_token_format(self):
        from ldapx.parser.validation import get_attribute_token_format
        from ldapx.parser.consts import TOKENSTRINGUNICODE
        # Known attr
        result = get_attribute_token_format("cn")
        assert result == TOKENSTRINGUNICODE
        # Unknown attr defaults to TOKENSTRINGUNICODE
        result = get_attribute_token_format("nonexistent")
        assert result == TOKENSTRINGUNICODE
