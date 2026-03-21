"""
LDAP filter parser - Python port of ldapx parser/filter.go

Parses LDAP filter strings into an AST and converts back.
References:
  - RFC4510 - LDAP: Technical Specification
  - RFC4515 - LDAP: String Representation of Search Filters
  - DEFCON32 - MaLDAPtive
"""

import re


class Filter:
    pass


class FilterAnd(Filter):
    def __init__(self, filters):
        self.filters = filters


class FilterOr(Filter):
    def __init__(self, filters):
        self.filters = filters


class FilterNot(Filter):
    def __init__(self, filter_):
        self.filter = filter_


class FilterEqualityMatch(Filter):
    def __init__(self, attribute_desc, assertion_value):
        self.attribute_desc = attribute_desc
        self.assertion_value = assertion_value


class FilterPresent(Filter):
    def __init__(self, attribute_desc):
        self.attribute_desc = attribute_desc


class FilterSubstring(Filter):
    def __init__(self, attribute_desc, substrings):
        self.attribute_desc = attribute_desc
        self.substrings = substrings  # list of SubstringFilter


class SubstringFilter:
    def __init__(self, initial="", any_="", final=""):
        self.initial = initial
        self.any = any_
        self.final = final


class FilterGreaterOrEqual(Filter):
    def __init__(self, attribute_desc, assertion_value):
        self.attribute_desc = attribute_desc
        self.assertion_value = assertion_value


class FilterLessOrEqual(Filter):
    def __init__(self, attribute_desc, assertion_value):
        self.attribute_desc = attribute_desc
        self.assertion_value = assertion_value


class FilterApproxMatch(Filter):
    def __init__(self, attribute_desc, assertion_value):
        self.attribute_desc = attribute_desc
        self.assertion_value = assertion_value


class FilterExtensibleMatch(Filter):
    def __init__(self, matching_rule="", attribute_desc="", match_value="", dn_attributes=False):
        self.matching_rule = matching_rule
        self.attribute_desc = attribute_desc
        self.match_value = match_value
        self.dn_attributes = dn_attributes


def _ldap_escape(s):
    s = s.replace("\\", "\\\\")
    s = s.replace("(", "\\(")
    s = s.replace(")", "\\)")
    return s


def _decode_escaped(s):
    result = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 2 < len(s):
            try:
                byte_val = int(s[i+1:i+3], 16)
                result.append(chr(byte_val))
                i += 3
                continue
            except ValueError:
                pass
        result.append(s[i])
        i += 1
    return "".join(result)


def filter_to_query(f):
    """Convert a Filter AST node to an LDAP filter string."""
    if isinstance(f, FilterAnd):
        subs = "".join(filter_to_query(sf) for sf in f.filters)
        return "(&" + subs + ")"

    if isinstance(f, FilterOr):
        subs = "".join(filter_to_query(sf) for sf in f.filters)
        return "(|" + subs + ")"

    if isinstance(f, FilterNot):
        return "(!" + filter_to_query(f.filter) + ")"

    if isinstance(f, FilterEqualityMatch):
        return "(%s=%s)" % (_ldap_escape(f.attribute_desc), _ldap_escape(f.assertion_value))

    if isinstance(f, FilterSubstring):
        parts = []
        for sub in f.substrings:
            if sub.initial:
                parts.append(_ldap_escape(sub.initial))
            elif sub.any:
                parts.append(_ldap_escape(sub.any))
            elif sub.final:
                parts.append(_ldap_escape(sub.final))
        if parts:
            if not f.substrings[0].initial:
                parts[0] = "*" + parts[0]
            if not f.substrings[-1].final:
                parts[-1] = parts[-1] + "*"
        return "(%s=%s)" % (_ldap_escape(f.attribute_desc), "*".join(parts))

    if isinstance(f, FilterGreaterOrEqual):
        return "(%s>=%s)" % (_ldap_escape(f.attribute_desc), _ldap_escape(f.assertion_value))

    if isinstance(f, FilterLessOrEqual):
        return "(%s<=%s)" % (_ldap_escape(f.attribute_desc), _ldap_escape(f.assertion_value))

    if isinstance(f, FilterPresent):
        return "(%s=*)" % _ldap_escape(f.attribute_desc)

    if isinstance(f, FilterApproxMatch):
        return "(%s~=%s)" % (_ldap_escape(f.attribute_desc), _ldap_escape(f.assertion_value))

    if isinstance(f, FilterExtensibleMatch):
        parts = []
        if f.attribute_desc:
            parts.append(_ldap_escape(f.attribute_desc))
        if f.dn_attributes:
            parts.append("dn")
        if f.matching_rule:
            parts.append(_ldap_escape(f.matching_rule))
        if f.match_value:
            parts.append("=" + _ldap_escape(f.match_value))
        return "(%s)" % ":".join(parts)

    raise ValueError(f"Unsupported filter type: {type(f)}")


def query_to_filter(query):
    """Parse an LDAP filter string into a Filter AST."""
    query = query.strip()
    if not query:
        raise ValueError("Empty query string")
    if query[0] != "(" or query[-1] != ")":
        raise ValueError("Invalid query format")

    c = query[1]
    if c == "&":
        return _parse_and_filter(query)
    elif c == "|":
        return _parse_or_filter(query)
    elif c == "!":
        return _parse_not_filter(query)
    else:
        return _parse_simple_filter(query)


def _parse_and_filter(query):
    sub_filters = _parse_sub_filters(query[2:-1])
    return FilterAnd(sub_filters)


def _parse_or_filter(query):
    sub_filters = _parse_sub_filters(query[2:-1])
    return FilterOr(sub_filters)


def _parse_not_filter(query):
    if len(query) < 4:
        raise ValueError("Invalid NOT filter")
    sub = query_to_filter(query[2:-1])
    return FilterNot(sub)


def _parse_sub_filters(query):
    filters = []
    current = ""
    depth = 0
    for ch in query:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        current += ch
        if depth == 0 and current:
            filters.append(query_to_filter(current))
            current = ""
    return filters


def _parse_simple_filter(query):
    STATE_ATTR = 0
    STATE_EXTENSIBLE_RULE = 1
    STATE_CONDITION = 2

    dn_attributes = False
    attribute = []
    matching_rule = []
    condition = []

    query = query.strip()
    if len(query) < 3 or query[0] != "(" or query[-1] != ")":
        raise ValueError("Invalid simple filter format")

    result_type = None
    state = STATE_ATTR
    inner = query[1:-1]  # strip outer parens

    i = 0
    while i < len(inner):
        remaining = inner[i:]
        ch = inner[i]

        if state == STATE_ATTR:
            if remaining.startswith(":dn:="):
                dn_attributes = True
                state = STATE_CONDITION
                result_type = "extensible"
                i += 5
            elif remaining.startswith(":dn:"):
                dn_attributes = True
                state = STATE_EXTENSIBLE_RULE
                result_type = "extensible"
                i += 4
            elif remaining.startswith(":="):
                state = STATE_CONDITION
                result_type = "extensible"
                i += 2
            elif ch == ":":
                state = STATE_EXTENSIBLE_RULE
                result_type = "extensible"
                i += 1
            elif ch == "=":
                state = STATE_CONDITION
                result_type = "equality"
                i += 1
            elif remaining.startswith(">="):
                state = STATE_CONDITION
                result_type = "gte"
                i += 2
            elif remaining.startswith("<="):
                state = STATE_CONDITION
                result_type = "lte"
                i += 2
            elif remaining.startswith("~="):
                state = STATE_CONDITION
                result_type = "approx"
                i += 2
            else:
                attribute.append(ch)
                i += 1

        elif state == STATE_EXTENSIBLE_RULE:
            if remaining.startswith(":="):
                state = STATE_CONDITION
                i += 2
            else:
                matching_rule.append(ch)
                i += 1

        elif state == STATE_CONDITION:
            condition.append(ch)
            i += 1

    attr_str = "".join(attribute)
    cond_str = "".join(condition)
    decoded = _decode_escaped(cond_str)

    if result_type == "extensible":
        return FilterExtensibleMatch(
            matching_rule="".join(matching_rule),
            attribute_desc=attr_str,
            match_value=decoded,
            dn_attributes=dn_attributes,
        )
    elif result_type == "approx":
        return FilterApproxMatch(attr_str, decoded)
    elif result_type == "gte":
        return FilterGreaterOrEqual(attr_str, decoded)
    elif result_type == "lte":
        return FilterLessOrEqual(attr_str, decoded)
    elif result_type == "equality":
        if cond_str == "*":
            return FilterPresent(attr_str)
        elif "*" in cond_str:
            parts = cond_str.split("*")
            substrings = []
            for idx, part in enumerate(parts):
                if not part:
                    continue
                decoded_part = _decode_escaped(part)
                if idx == 0:
                    substrings.append(SubstringFilter(initial=decoded_part))
                elif idx == len(parts) - 1:
                    substrings.append(SubstringFilter(final=decoded_part))
                else:
                    substrings.append(SubstringFilter(any_=decoded_part))
            return FilterSubstring(attr_str, substrings)
        else:
            return FilterEqualityMatch(attr_str, decoded)

    raise ValueError(f"Could not parse filter: {query}")
