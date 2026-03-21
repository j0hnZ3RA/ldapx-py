"""Tests for filter obfuscation middlewares."""

import random
import pytest

from ldapx.parser import query_to_filter, filter_to_query
from ldapx.middlewares.filter import (
    rand_case_filter_obf,
    oid_attribute_filter_obf,
    rand_garbage_filter_obf,
    rand_bool_reorder_filter_obf,
    rand_dbl_neg_bool_filter_obf,
    de_morgan_bool_filter_obf,
    equality_to_approx_match_filter_obf,
    equality_to_extensible_filter_obf,
    replace_tautologies_filter_obf,
)


class TestFilterObfuscation:
    def test_case_obfuscation_produces_valid_filter(self):
        random.seed(42)
        f = query_to_filter("(cn=admin)")
        result = rand_case_filter_obf(1.0)(f)
        output = filter_to_query(result)
        assert output.startswith("(")
        assert output.endswith(")")
        assert "=" in output

    def test_oid_attribute_obfuscation(self):
        random.seed(42)
        f = query_to_filter("(cn=admin)")
        result = oid_attribute_filter_obf(0, 0)(f)
        output = filter_to_query(result)
        assert "oID." in output or "2.5.4.3" in output

    def test_garbage_obfuscation_wraps_in_or(self):
        random.seed(42)
        f = query_to_filter("(cn=admin)")
        result = rand_garbage_filter_obf(1, 5)(f)
        output = filter_to_query(result)
        assert output.startswith("(|")

    def test_bool_reorder_preserves_structure(self):
        random.seed(42)
        f = query_to_filter("(&(cn=a)(sn=b)(objectClass=user))")
        result = rand_bool_reorder_filter_obf()(f)
        output = filter_to_query(result)
        assert output.startswith("(&")
        assert "(cn=a)" in output
        assert "(sn=b)" in output
        assert "(objectClass=user)" in output

    def test_double_negation(self):
        random.seed(42)
        f = query_to_filter("(cn=admin)")
        result = rand_dbl_neg_bool_filter_obf(2, 1.0)(f)
        output = filter_to_query(result)
        assert "(!(!" in output

    def test_de_morgan(self):
        f = query_to_filter("(&(cn=a)(sn=b))")
        result = de_morgan_bool_filter_obf()(f)
        output = filter_to_query(result)
        assert "(!" in output
        assert "(|" in output

    def test_approx_match(self):
        f = query_to_filter("(cn=admin)")
        result = equality_to_approx_match_filter_obf()(f)
        output = filter_to_query(result)
        assert "~=" in output

    def test_extensible_match(self):
        f = query_to_filter("(cn=admin)")
        result = equality_to_extensible_filter_obf()(f)
        output = filter_to_query(result)
        assert ":=" in output

    def test_tautologies_on_objectclass(self):
        random.seed(42)
        f = query_to_filter("(objectClass=*)")
        result = replace_tautologies_filter_obf()(f)
        output = filter_to_query(result)
        # Should be replaced with a tautology (not just objectClass=*)
        assert len(output) > len("(objectClass=*)")


class TestChainComposition:
    def test_multiple_middlewares(self):
        random.seed(42)
        f = query_to_filter("(cn=admin)")
        f = rand_case_filter_obf(0.5)(f)
        f = oid_attribute_filter_obf(1, 1)(f)
        output = filter_to_query(f)
        assert "oID." in output or "2.5.4.3" in output
