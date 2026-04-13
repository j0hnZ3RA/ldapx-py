"""
AttrList obfuscation middlewares - Python port of ldapx middlewares/attrlist/obfuscation.go
"""

import random
import string

from ldapx.parser.consts import OIDS_MAP, ATTR_CONTEXTS, ROOTDSE_OPERATIONAL_ATTRS, RFC_OPERATIONAL_ATTRS
from ldapx.parser.validation import is_oid
from ldapx.middlewares.helpers.string import (
    randomly_change_case_string, randomly_prepend_zeros_oid,
    generate_garbage_string, apply_oid_prefix,
)


def rand_case_attrlist_obf(prob=0.5):
    def mw(attrs):
        return [randomly_change_case_string(a, prob) for a in attrs]
    return mw


def oid_attribute_attrlist_obf(max_spaces=2, max_zeros=2, include_prefix=True):
    def mw(attrs):
        result = []
        for attr in attrs:
            name = attr
            oid = OIDS_MAP.get(attr.lower())
            if oid:
                name = oid
            if is_oid(name):
                if max_spaces > 0:
                    name += " " * (1 + random.randint(0, max_spaces - 1))
                if max_zeros > 0:
                    name = randomly_prepend_zeros_oid(name, max_zeros)
                name = apply_oid_prefix(name, include_prefix)
            result.append(name)
        return result
    return mw


def duplicate_attrlist_obf(prob=0.3):
    def mw(attrs):
        result = []
        for attr in attrs:
            result.append(attr)
            if random.random() < prob:
                result.append(attr)
        if attrs and len(result) == len(attrs):
            result.append(random.choice(attrs))
        return result
    return mw


def garbage_existing_attrlist_obf(max_garbage=2):
    existing = list(ATTR_CONTEXTS.keys())

    def mw(attrs):
        if not attrs:
            return attrs
        if max_garbage <= 0:
            return list(attrs)
        result = list(attrs)
        count = 1 + random.randint(0, max_garbage - 1)
        for _ in range(count):
            result.append(random.choice(existing))
        return result
    return mw


def garbage_non_existing_attrlist_obf(max_garbage=2, garbage_size=10, charset=string.ascii_letters):
    def mw(attrs):
        if not attrs:
            return attrs
        if max_garbage <= 0:
            return list(attrs)
        result = list(attrs)
        count = 1 + random.randint(0, max_garbage - 1)
        for _ in range(count):
            for _ in range(100):
                garbage = generate_garbage_string(garbage_size, charset)
                if garbage.lower() not in OIDS_MAP:
                    result.append(garbage)
                    break
        return result
    return mw


def add_wildcard_attrlist_obf():
    """Add '*' to the attribute list. Note: changes what the server returns."""
    def mw(attrs):
        return list(attrs) + ["*"]
    return mw


def add_plus_attrlist_obf():
    """Add '+' (operational attributes) to the list. Note: changes what the server returns."""
    def mw(attrs):
        result = list(attrs)
        if not attrs:
            result.append("*")
        result.append("+")
        return result
    return mw


def replace_with_wildcard_attrlist_obf():
    """Replace attribute list with '*'. Note: changes what the server returns."""
    def mw(attrs):
        new_attrs = ["*"]
        for attr in attrs:
            if attr == "+":
                new_attrs.append("+")
            elif attr.lower() in ROOTDSE_OPERATIONAL_ATTRS or attr.lower() in RFC_OPERATIONAL_ATTRS:
                new_attrs.append(attr)
        return new_attrs
    return mw


def replace_with_empty_attrlist_obf():
    """Replace attribute list with empty (server returns all). Note: changes what the server returns."""
    def mw(attrs):
        new_attrs = []
        for attr in attrs:
            if attr == "+":
                new_attrs.append("+")
            elif attr.lower() in ROOTDSE_OPERATIONAL_ATTRS or attr.lower() in RFC_OPERATIONAL_ATTRS:
                new_attrs.append(attr)
        if new_attrs:
            new_attrs = ["*"] + new_attrs
        return new_attrs
    return mw


def reorder_list_attrlist_obf():
    def mw(attrs):
        result = list(attrs)
        random.shuffle(result)
        return result
    return mw
