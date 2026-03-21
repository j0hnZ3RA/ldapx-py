"""Tests for string manipulation helpers."""

import random
import pytest

from ldapx.middlewares.helpers.string import (
    generate_garbage_string,
    hex_encode_char,
    randomly_hex_encode_string,
    randomly_change_case_string,
    randomly_prepend_zeros_oid,
    randomly_hex_encode_dn_string,
    replace_timestamp,
    prepend_zeros_to_sid,
    prepend_zeros_to_number,
    add_anr_spacing,
    add_dn_spacing,
    add_sid_spacing,
    get_next_string,
    get_previous_string,
    get_next_sid,
    get_previous_sid,
    split_slice,
    CHAR_ORDERING,
)


class TestGarbageString:
    def test_length(self):
        result = generate_garbage_string(10)
        assert len(result) == 10

    def test_zero_length(self):
        result = generate_garbage_string(0)
        assert result == ""

    def test_custom_charset(self):
        result = generate_garbage_string(20, "abc")
        assert all(c in "abc" for c in result)


class TestHexEncoding:
    def test_hex_encode_char(self):
        assert hex_encode_char("A") == "\\41"
        assert hex_encode_char("a") == "\\61"
        assert hex_encode_char("0") == "\\30"

    def test_randomly_hex_encode_string_full(self):
        random.seed(42)
        result = randomly_hex_encode_string("abc", 1.0)
        assert "\\" in result
        assert len(result) > 3  # hex encoding makes it longer

    def test_randomly_hex_encode_string_none(self):
        result = randomly_hex_encode_string("abc", 0.0)
        assert result == "abc"


class TestCaseMutation:
    def test_no_mutation(self):
        result = randomly_change_case_string("hello", 0.0)
        assert result == "hello"

    def test_full_mutation_preserves_content(self):
        random.seed(42)
        result = randomly_change_case_string("hello", 1.0)
        assert result.lower() == "hello"

    def test_non_alpha_preserved(self):
        result = randomly_change_case_string("123!@#", 1.0)
        assert result == "123!@#"


class TestOIDManipulation:
    def test_prepend_zeros(self):
        random.seed(42)
        result = randomly_prepend_zeros_oid("1.2.3", 2)
        parts = result.split(".")
        assert len(parts) == 3
        # Each part should end with the original digit
        assert parts[0].endswith("1")
        assert parts[1].endswith("2")
        assert parts[2].endswith("3")

    def test_oid_prefix_preserved(self):
        random.seed(42)
        result = randomly_prepend_zeros_oid("OID.1.2.3", 2)
        assert result.startswith("OID.")


class TestDNHelpers:
    def test_hex_encode_dn_string(self):
        random.seed(42)
        result = randomly_hex_encode_dn_string("CN=admin,DC=corp", 1.0)
        assert "CN=" in result
        assert "DC=" in result

    def test_add_dn_spacing(self):
        random.seed(42)
        result = add_dn_spacing("CN=admin,DC=corp", 2)
        assert "=" in result
        assert "," in result

    def test_add_sid_spacing(self):
        random.seed(42)
        result = add_sid_spacing("S-1-5-21-123", 2)
        assert "-" in result
        # Structure preserved
        parts = result.split("-")
        assert len(parts) == 5

    def test_add_anr_spacing(self):
        random.seed(42)
        result = add_anr_spacing("=admin", 3)
        assert "admin" in result


class TestTimestamp:
    def test_replace_timestamp_valid(self):
        random.seed(42)
        result = replace_timestamp("20230812120000.0Z", 3, "0123456789", False)
        assert result.startswith("20230812120000")
        assert "Z" in result

    def test_replace_timestamp_invalid(self):
        result = replace_timestamp("not-a-timestamp", 3, "0123456789", False)
        assert result == "not-a-timestamp"


class TestSIDHelpers:
    def test_prepend_zeros_to_sid(self):
        random.seed(42)
        result = prepend_zeros_to_sid("S-1-5-21-123-456", 3)
        assert result.startswith("S-")
        assert "-" in result

    def test_prepend_zeros_to_number(self):
        result = prepend_zeros_to_number("42", 3)
        assert result.endswith("42")

    def test_prepend_zeros_negative(self):
        result = prepend_zeros_to_number("-42", 3)
        assert result.startswith("-")
        assert result.endswith("42")


class TestStringComparison:
    def test_get_next_string(self):
        result = get_next_string("a")
        assert result == "b"

    def test_get_previous_string(self):
        result = get_previous_string("b")
        assert result == "a"

    def test_get_next_string_overflow(self):
        last = CHAR_ORDERING[-1]
        result = get_next_string(last)
        # Should wrap and add char
        assert len(result) == 2

    def test_get_previous_string_underflow(self):
        first = CHAR_ORDERING[0]
        result = get_previous_string(first)
        # Single char at beginning stays the same
        assert result == first

    def test_get_next_sid(self):
        assert get_next_sid("S-1-5-21-500") == "S-1-5-21-501"

    def test_get_previous_sid(self):
        assert get_previous_sid("S-1-5-21-500") == "S-1-5-21-499"

    def test_get_previous_sid_zero(self):
        assert get_previous_sid("S-1-5-21-0") == "S-1-5-21-0"


class TestSplitSlice:
    def test_split_middle(self):
        before, after = split_slice([1, 2, 3, 4, 5], 2)
        assert before == [1, 2]
        assert after == [4, 5]

    def test_split_first(self):
        before, after = split_slice([1, 2, 3], 0)
        assert before == []
        assert after == [2, 3]

    def test_split_last(self):
        before, after = split_slice([1, 2, 3], 2)
        assert before == [1, 2]
        assert after == []
