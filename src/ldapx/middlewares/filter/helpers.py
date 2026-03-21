"""
Filter middleware helpers - leaf applier and garbage filter generation.
"""

import random
import string

from ldapx.parser.filter import (
    Filter, FilterAnd, FilterOr, FilterNot,
    FilterEqualityMatch, FilterSubstring, FilterPresent,
    FilterGreaterOrEqual, FilterLessOrEqual, FilterApproxMatch,
    FilterExtensibleMatch, SubstringFilter,
)
from ldapx.middlewares.helpers.string import generate_garbage_string


def leaf_applier(middleware):
    """Applies a middleware function to all leaf nodes of a filter tree."""
    def applier(filter_):
        if isinstance(filter_, FilterAnd):
            return FilterAnd([applier(sf) for sf in filter_.filters])
        elif isinstance(filter_, FilterOr):
            return FilterOr([applier(sf) for sf in filter_.filters])
        elif isinstance(filter_, FilterNot):
            return FilterNot(applier(filter_.filter))
        else:
            return middleware(filter_)
    return applier


def map_to_oid(attr_name):
    """Look up the OID for an attribute name."""
    from ldapx.parser.consts import OIDS_MAP
    return OIDS_MAP.get(attr_name.lower(), None)


def generate_garbage_filter(attr="", garbage_size=10, chars=string.ascii_letters):
    """Generate a random garbage LDAP filter."""
    def garbage():
        return generate_garbage_string(garbage_size, chars)

    generators = [
        lambda: FilterEqualityMatch(attr or garbage(), garbage()),
        lambda: FilterApproxMatch(attr or garbage(), garbage()),
        lambda: _generate_substring_garbage(attr or garbage(), garbage_size, chars),
        lambda: FilterLessOrEqual(attr or garbage(), garbage()),
        lambda: FilterGreaterOrEqual(attr or garbage(), garbage()),
        lambda: FilterExtensibleMatch(garbage(), attr or garbage(), garbage()),
    ]

    return random.choice(generators)()


def _generate_substring_garbage(attr_name, garbage_size, chars):
    def garbage():
        return generate_garbage_string(garbage_size, chars)

    pattern = random.randint(0, 3)
    subs = []
    if pattern == 0:
        subs.append(SubstringFilter(initial=garbage()))
    elif pattern == 1:
        subs.append(SubstringFilter(final=garbage()))
    elif pattern == 2:
        subs.append(SubstringFilter(initial=garbage()))
        subs.append(SubstringFilter(final=garbage()))
    else:
        subs.append(SubstringFilter(initial=garbage()))
        for _ in range(random.randint(0, 2)):
            subs.append(SubstringFilter(any_=garbage()))
        if random.randint(0, 1) == 0:
            subs.append(SubstringFilter(final=garbage()))
    return FilterSubstring(attr_name, subs)
