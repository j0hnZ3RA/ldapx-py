"""
AttrEntries obfuscation middlewares - Python port of ldapx middlewares/attrentries/obfuscation.go

Used to obfuscate attribute names in Modify and Add operations.
"""

import random

from ldapx.parser.consts import OIDS_MAP
from ldapx.middlewares.helpers.string import randomly_change_case_string


def _normalize_values(values):
    if isinstance(values, list):
        return list(values)
    if isinstance(values, tuple):
        return list(values)
    return [values]


def rand_case_attrentries_obf(prob=0.5):
    def mw(entries):
        result = {}
        for name, values in entries.items():
            new_name = randomly_change_case_string(name, prob)
            if new_name in result:
                result[new_name].extend(_normalize_values(values))
            else:
                result[new_name] = _normalize_values(values)
        return result
    return mw


def oid_attribute_attrentries_obf():
    """Replace attribute names with plain OIDs for modify/add operations.

    Note: AD's modify/add handler requires strict OID format. This uses
    clean OIDs without the oID. prefix, prepended zeros, or trailing spaces.
    May not work with all AD operations - test before using.
    """
    def mw(entries):
        result = {}
        for name, values in entries.items():
            oid = OIDS_MAP.get(name.lower())
            out_name = oid if oid else name
            if out_name in result:
                result[out_name].extend(_normalize_values(values))
            else:
                result[out_name] = _normalize_values(values)
        return result
    return mw


def reorder_list_attrentries_obf():
    def mw(entries):
        items = list(entries.items())
        random.shuffle(items)
        return dict(items)
    return mw
