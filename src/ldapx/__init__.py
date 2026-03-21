"""
ldapx - LDAP query obfuscation library
Python port of github.com/Macmod/ldapx

Provides obfuscation for LDAP filters, BaseDN, attribute lists,
and attribute entries (for modify/add operations).

Usage:
    import ldapx

    # High-level (chain string)
    result = ldapx.obfuscate_filter("(cn=admin)", "COGDR")
    result = ldapx.obfuscate_basedn("DC=corp,DC=local", "CSQOX")
    result = ldapx.obfuscate_attrlist(["cn", "sAMAccountName"], "CRDG")
    result = ldapx.obfuscate_attrentries({"cn": [b"test"]}, "CR")

    # Direct middleware composition
    from ldapx.parser import query_to_filter, filter_to_query
    from ldapx.middlewares.filter import rand_case_filter_obf, oid_attribute_filter_obf

    f = query_to_filter("(cn=admin)")
    f = rand_case_filter_obf(0.5)(f)
    f = oid_attribute_filter_obf(2, 2)(f)
    result = filter_to_query(f)

Chain codes:

Filter chain codes:
  C - Random case          S - Random spacing        G - Garbage filters
  T - Replace tautologies  R - Boolean reorder       O - OID attributes
  X - Hex value encoding   t - Timestamp garbage     B - Add random boolean
  D - Double negation      M - DeMorgan transform    b - Bitwise breakout
  d - Bitwise decompose    I - Equality by inclusion E - Equality by exclusion
  A - Approx match         x - Extensible match      Z - Prepend zeros
  s - Substring split      N - Names to ANR          n - ANR garbage substring
  P - dnAttributes noise   L - Transitive eval (link attrs)

BaseDN chain codes:
  C - Random case          S - Random spacing        Q - Double quotes
  O - OID attributes       X - Hex value encoding
  U - GUID format (requires BaseDNGuid option)
  I - SID format (requires BaseDNSid option)

AttrList chain codes:
  C - Random case          R - Reorder list          D - Duplicate
  O - OID attributes       G - Garbage (non-existing) g - Garbage (existing)
  W - Replace with wildcard  w - Add wildcard        p - Add plus (operational)
  e - Replace with empty

AttrEntries chain codes:
  C - Random case          R - Reorder list          O - OID attributes
"""

import logging
import string

from ._version import __version__
from .parser import query_to_filter, filter_to_query
from .middlewares.options import Options
from .middlewares.filter.obfuscation import (
    rand_case_filter_obf, rand_spacing_filter_obf, rand_garbage_filter_obf,
    replace_tautologies_filter_obf, rand_bool_reorder_filter_obf,
    oid_attribute_filter_obf, rand_hex_value_filter_obf,
    rand_timestamp_suffix_filter_obf, rand_add_bool_filter_obf,
    rand_dbl_neg_bool_filter_obf, de_morgan_bool_filter_obf,
    exact_bitwise_breakout_filter_obf, bitwise_decompose_filter_obf,
    equality_by_inclusion_filter_obf, equality_by_exclusion_filter_obf,
    equality_to_approx_match_filter_obf, equality_to_extensible_filter_obf,
    rand_prepend_zeros_filter_obf, rand_substring_split_filter_obf,
    anr_attribute_filter_obf, anr_substring_garbage_filter_obf,
    rand_dn_attributes_noise_filter_obf, transitive_eval_filter_obf,
)
from .middlewares.basedn.obfuscation import (
    rand_case_basedn_obf, rand_spacing_basedn_obf, double_quotes_basedn_obf,
    oid_attribute_basedn_obf, guid_basedn_obf, sid_basedn_obf,
    rand_hex_value_basedn_obf,
)
from .middlewares.attrlist.obfuscation import (
    rand_case_attrlist_obf, reorder_list_attrlist_obf, duplicate_attrlist_obf,
    oid_attribute_attrlist_obf, garbage_non_existing_attrlist_obf,
    garbage_existing_attrlist_obf, replace_with_wildcard_attrlist_obf,
    add_wildcard_attrlist_obf, add_plus_attrlist_obf,
    replace_with_empty_attrlist_obf,
)
from .middlewares.attrentries.obfuscation import (
    rand_case_attrentries_obf, oid_attribute_attrentries_obf,
    reorder_list_attrentries_obf,
)

LOG = logging.getLogger(__name__)

# ANSI color codes for verbose output
_CYAN = "\033[36m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_RESET = "\033[0m"
_DIM = "\033[2m"


def _verbose_log(op, **fields):
    """Log obfuscation details with colored output (original vs obfuscated)."""
    parts = [f"{_CYAN}[ldapx]{_RESET} {op}"]
    for k, v in fields.items():
        if v is not None:
            if "original" in k:
                parts.append(f"  {_RED}{k}:{_RESET} {v}")
            elif "obfuscated" in k:
                parts.append(f"  {_GREEN}{k}:{_RESET} {v}")
            else:
                parts.append(f"  {_YELLOW}{k}:{_RESET} {v}")
    LOG.warning("\n".join(parts))


# Default ANR attribute set
_ANR_SET = {
    "cn", "displayname", "givenname", "legacyexchangedn", "msds-additionaldnshostname",
    "msds-phoneticcompanyname", "msds-phoneticdepartment", "msds-phoneticdisplayname",
    "msds-phoneticfirstname", "msds-phoneticlastname", "name", "physicaldeliveryofficename",
    "proxyaddresses", "rdn", "samaccountname", "sn",
}


def _build_filter_middlewares(opts=None):
    """Build filter middleware map from options."""
    if opts is None:
        opts = Options()
    return {
        "C": lambda: rand_case_filter_obf(opts.get("FiltCaseProb")),
        "S": lambda: rand_spacing_filter_obf(opts.get("FiltSpacingMaxSpaces")),
        "G": lambda: rand_garbage_filter_obf(opts.get("FiltGarbageMaxElems"), opts.get("FiltGarbageSize")),
        "T": lambda: replace_tautologies_filter_obf(),
        "R": lambda: rand_bool_reorder_filter_obf(),
        "O": lambda: oid_attribute_filter_obf(opts.get("FiltOIDMaxSpaces"), opts.get("FiltOIDMaxZeros"), opts.get("FiltOIDIncludePrefix")),
        "X": lambda: rand_hex_value_filter_obf(opts.get("FiltHexValueProb")),
        "t": lambda: rand_timestamp_suffix_filter_obf(opts.get("FiltTimestampMaxChars"), string.digits, opts.get("FiltTimestampUseComma")),
        "B": lambda: rand_add_bool_filter_obf(opts.get("FiltBoolMaxDepth"), opts.get("FiltBoolProb")),
        "D": lambda: rand_dbl_neg_bool_filter_obf(opts.get("FiltBoolMaxDepth"), opts.get("FiltBoolProb")),
        "M": lambda: de_morgan_bool_filter_obf(),
        "b": lambda: exact_bitwise_breakout_filter_obf(),
        "d": lambda: bitwise_decompose_filter_obf(opts.get("FiltBitwiseMaxBits")),
        "I": lambda: equality_by_inclusion_filter_obf(),
        "E": lambda: equality_by_exclusion_filter_obf(),
        "A": lambda: equality_to_approx_match_filter_obf(),
        "x": lambda: equality_to_extensible_filter_obf(),
        "Z": lambda: rand_prepend_zeros_filter_obf(opts.get("FiltPrependZerosMax")),
        "s": lambda: rand_substring_split_filter_obf(opts.get("FiltSubstringSplitProb")),
        "N": lambda: anr_attribute_filter_obf(_ANR_SET),
        "n": lambda: anr_substring_garbage_filter_obf(opts.get("FiltANRGarbageMaxChars")),
        "P": lambda: rand_dn_attributes_noise_filter_obf(opts.get("FiltDNAttrNoiseProb", 0.5)),
        "L": lambda: transitive_eval_filter_obf(),
    }


def _build_basedn_middlewares(opts=None):
    if opts is None:
        opts = Options()
    return {
        "C": lambda: rand_case_basedn_obf(opts.get("BDNCaseProb")),
        "S": lambda: rand_spacing_basedn_obf(opts.get("BDNSpacingMaxSpaces")),
        "Q": lambda: double_quotes_basedn_obf(),
        "O": lambda: oid_attribute_basedn_obf(opts.get("BDNOIDMaxSpaces"), opts.get("BDNOIDMaxZeros"), opts.get("BDNOIDIncludePrefix")),
        "X": lambda: rand_hex_value_basedn_obf(opts.get("BDNHexValueProb")),
        "U": lambda: guid_basedn_obf(opts.get("BaseDNGuid", "")),
        "I": lambda: sid_basedn_obf(opts.get("BaseDNSid", "")),
    }


def _build_attrlist_middlewares(opts=None):
    if opts is None:
        opts = Options()
    return {
        "C": lambda: rand_case_attrlist_obf(opts.get("AttrsCaseProb")),
        "R": lambda: reorder_list_attrlist_obf(),
        "D": lambda: duplicate_attrlist_obf(opts.get("AttrsDuplicateProb")),
        "O": lambda: oid_attribute_attrlist_obf(opts.get("AttrsOIDMaxSpaces"), opts.get("AttrsOIDMaxZeros"), opts.get("AttrsOIDIncludePrefix")),
        "G": lambda: garbage_non_existing_attrlist_obf(opts.get("AttrsGarbageMaxElems"), opts.get("AttrsGarbageSize")),
        "g": lambda: garbage_existing_attrlist_obf(opts.get("AttrsExistingGarbageMax")),
        "W": lambda: replace_with_wildcard_attrlist_obf(),
        "w": lambda: add_wildcard_attrlist_obf(),
        "p": lambda: add_plus_attrlist_obf(),
        "e": lambda: replace_with_empty_attrlist_obf(),
    }


def _build_attrentries_middlewares(opts=None):
    if opts is None:
        opts = Options()
    return {
        "C": lambda: rand_case_attrentries_obf(opts.get("AttrEntriesCaseProb")),
        "R": lambda: reorder_list_attrentries_obf(),
        "O": lambda: oid_attribute_attrentries_obf(),
    }


def obfuscate_filter(filter_str, chain, options=None, verbose=False):
    """Apply filter obfuscation chain to an LDAP filter string.

    Args:
        filter_str: LDAP filter string to obfuscate.
        chain: Middleware chain string (e.g., "COGDR").
        options: Optional Options instance for middleware parameters.
        verbose: If True, log original vs obfuscated with colors.

    Returns the obfuscated filter as a string.
    For ASN1 conversion (e.g., badldap), use ldapx.adapters.badldap.ast_to_asn1().
    """
    if not filter_str or not chain:
        return filter_str
    try:
        f = query_to_filter(filter_str)
    except Exception as e:
        LOG.warning("Failed to parse filter for obfuscation: %s", e)
        return filter_str

    middlewares = _build_filter_middlewares(options)
    for code in chain:
        factory = middlewares.get(code)
        if factory:
            middleware = factory()
            f = middleware(f)
        else:
            LOG.warning("Unknown filter obfuscation code: %s", code)

    try:
        result = filter_to_query(f)
    except Exception as e:
        LOG.warning("Failed to convert obfuscated filter to string: %s", e)
        return filter_str

    if verbose:
        _verbose_log("FILTER",
            chain=chain,
            original=filter_str,
            obfuscated=result,
        )
    return result


def obfuscate_basedn(basedn, chain, options=None, verbose=False):
    """Apply BaseDN obfuscation chain to a BaseDN string.

    Args:
        basedn: BaseDN string to obfuscate.
        chain: Middleware chain string (e.g., "COQ").
        options: Optional Options instance for middleware parameters.
        verbose: If True, log original vs obfuscated with colors.
    """
    if not basedn or not chain:
        return basedn

    middlewares = _build_basedn_middlewares(options)
    result = basedn
    for code in chain:
        factory = middlewares.get(code)
        if factory:
            middleware = factory()
            result = middleware(result)
        else:
            LOG.warning("Unknown BaseDN obfuscation code: %s", code)

    if verbose:
        _verbose_log("BASEDN",
            chain=chain,
            original=basedn,
            obfuscated=result,
        )
    return result


def obfuscate_attrlist(attrs, chain, options=None, verbose=False):
    """Apply attribute list obfuscation chain.

    Args:
        attrs: List of attribute names to obfuscate.
        chain: Middleware chain string (e.g., "COR").
        options: Optional Options instance for middleware parameters.
        verbose: If True, log original vs obfuscated with colors.
    """
    if not attrs or not chain:
        return attrs

    middlewares = _build_attrlist_middlewares(options)
    result = list(attrs)
    for code in chain:
        factory = middlewares.get(code)
        if factory:
            middleware = factory()
            result = middleware(result)
        else:
            LOG.warning("Unknown AttrList obfuscation code: %s", code)

    if verbose:
        _verbose_log("ATTRLIST",
            chain=chain,
            original=", ".join(attrs),
            obfuscated=", ".join(result),
        )
    return result


def obfuscate_attrentries(entries, chain, options=None, verbose=False):
    """Apply attribute entries obfuscation chain (for modify/add ops).

    Args:
        entries: Dict of attribute names to values.
        chain: Middleware chain string (e.g., "CR").
        options: Optional Options instance for middleware parameters.
        verbose: If True, log original vs obfuscated with colors.
    """
    if not entries or not chain:
        return entries

    middlewares = _build_attrentries_middlewares(options)
    result = dict(entries)
    for code in chain:
        factory = middlewares.get(code)
        if factory:
            middleware = factory()
            result = middleware(result)
        else:
            LOG.warning("Unknown AttrEntries obfuscation code: %s", code)

    if verbose:
        _verbose_log("ATTRENTRIES",
            chain=chain,
            original=list(entries.keys()),
            obfuscated=list(result.keys()),
        )
    return result
