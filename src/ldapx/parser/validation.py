"""
Validation and attribute utilities for LDAP filter parsing.
"""

import re

from .consts import ATTR_CONTEXTS, TOKENSTRINGUNICODE

_OID_PATTERN = re.compile(r"^(?i:oid\.)?\d+(\.\d+)* *$")


def is_oid(s):
    """Check if a string is an OID (optionally prefixed with 'OID.')."""
    return bool(_OID_PATTERN.match(s))


def get_attribute_token_format(attr_name):
    """Get the token format type for an attribute name."""
    ctx = ATTR_CONTEXTS.get(attr_name.lower())
    if ctx is not None:
        return ctx
    return TOKENSTRINGUNICODE


def get_attr_name(filter_):
    """Extract the attribute name from a filter node, or None for boolean nodes."""
    from .filter import FilterAnd, FilterOr, FilterNot, FilterPresent, FilterExtensibleMatch

    if isinstance(filter_, (FilterAnd, FilterOr, FilterNot)):
        return None
    if isinstance(filter_, FilterPresent):
        return filter_.attribute_desc
    if isinstance(filter_, FilterExtensibleMatch):
        return filter_.attribute_desc
    if hasattr(filter_, "attribute_desc"):
        return filter_.attribute_desc
    return None
