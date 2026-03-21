"""
Converts ldapx filter AST directly to badldap ASN1 Filter objects.

This bypasses badldap's own PEG-based filter parser which cannot handle
many of the obfuscated filter syntaxes that ldapx produces (extensible
match, OID attributes with spacing, etc.).

Requires: pip install ldapx[badldap]
"""

try:
    from badldap.protocol.messages import (
        Filter as ASN1Filter,
        Filters as ASN1Filters,
        AttributeDescription,
        SubstringFilter as ASN1SubstringFilter,
        Substrings,
        Substring,
        MatchingRuleAssertion,
    )
    from badldap.protocol.query import rfc4515_encode
    _HAS_BADLDAP = True
except ImportError:
    _HAS_BADLDAP = False

from ldapx.parser.filter import (
    FilterAnd, FilterOr, FilterNot,
    FilterEqualityMatch, FilterSubstring, FilterPresent,
    FilterGreaterOrEqual, FilterLessOrEqual,
    FilterApproxMatch, FilterExtensibleMatch,
)


def ast_to_asn1(f):
    """Convert an ldapx filter AST node to a badldap ASN1 Filter.

    Raises ImportError if badldap is not installed.
    """
    if not _HAS_BADLDAP:
        raise ImportError(
            "badldap is required for ASN1 conversion. "
            "Install with: pip install ldapx[badldap]"
        )

    if isinstance(f, FilterAnd):
        return ASN1Filter({
            'and': ASN1Filters([ast_to_asn1(sf) for sf in f.filters])
        })

    if isinstance(f, FilterOr):
        return ASN1Filter({
            'or': ASN1Filters([ast_to_asn1(sf) for sf in f.filters])
        })

    if isinstance(f, FilterNot):
        return ASN1Filter({
            'not': ast_to_asn1(f.filter)
        })

    if isinstance(f, FilterPresent):
        return ASN1Filter({
            'present': AttributeDescription(f.attribute_desc.encode())
        })

    if isinstance(f, FilterEqualityMatch):
        return ASN1Filter({
            'equalityMatch': {
                'attributeDesc': f.attribute_desc.encode(),
                'assertionValue': _encode_value(f.assertion_value),
            }
        })

    if isinstance(f, FilterSubstring):
        subs = []
        for sub in f.substrings:
            if sub.initial:
                subs.append(Substring({'initial': _encode_value(sub.initial)}))
            elif sub.any:
                subs.append(Substring({'any': _encode_value(sub.any)}))
            elif sub.final:
                subs.append(Substring({'final': _encode_value(sub.final)}))
        return ASN1Filter({
            'substrings': ASN1SubstringFilter({
                'type': f.attribute_desc.encode(),
                'substrings': Substrings(subs),
            })
        })

    if isinstance(f, FilterGreaterOrEqual):
        return ASN1Filter({
            'greaterOrEqual': {
                'attributeDesc': f.attribute_desc.encode(),
                'assertionValue': _encode_value(f.assertion_value),
            }
        })

    if isinstance(f, FilterLessOrEqual):
        return ASN1Filter({
            'lessOrEqual': {
                'attributeDesc': f.attribute_desc.encode(),
                'assertionValue': _encode_value(f.assertion_value),
            }
        })

    if isinstance(f, FilterApproxMatch):
        return ASN1Filter({
            'approxMatch': {
                'attributeDesc': f.attribute_desc.encode(),
                'assertionValue': _encode_value(f.assertion_value),
            }
        })

    if isinstance(f, FilterExtensibleMatch):
        mra = {}
        if f.matching_rule:
            mra['matchingRule'] = f.matching_rule.encode()
        if f.attribute_desc:
            mra['type'] = f.attribute_desc.encode()
        mra['matchValue'] = _encode_value(f.match_value)
        mra['dnAttributes'] = f.dn_attributes
        return ASN1Filter({
            'extensibleMatch': MatchingRuleAssertion(mra)
        })

    raise ValueError(f"Unsupported filter AST type: {type(f)}")


def _encode_value(value):
    """Encode a filter value string to bytes using RFC4515 escaping."""
    return rfc4515_encode(value)
