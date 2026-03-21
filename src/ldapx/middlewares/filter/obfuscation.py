"""
Filter obfuscation middlewares - Python port of ldapx middlewares/filter/obfuscation.go

References:
  - DEFCON32 - MaLDAPtive
  - Microsoft Open Specifications - MS-ADTS
"""

import random
import string

from ldapx.parser.filter import (
    Filter, FilterAnd, FilterOr, FilterNot,
    FilterEqualityMatch, FilterSubstring, FilterPresent,
    FilterGreaterOrEqual, FilterLessOrEqual, FilterApproxMatch,
    FilterExtensibleMatch, SubstringFilter,
)
from ldapx.parser.validation import is_oid, get_attribute_token_format, get_attr_name
from ldapx.parser.consts import (
    OIDS_MAP, ATTR_CONTEXTS, TOKENDNSTRING, TOKENSID,
    TOKENSTRINGUNICODE, NUMBER_FORMATS, BITWISE_ATTRS,
)
from ldapx.middlewares.helpers.string import (
    randomly_change_case_string, randomly_hex_encode_string,
    randomly_prepend_zeros_oid, generate_garbage_string,
    randomly_hex_encode_dn_string, replace_timestamp,
    prepend_zeros_to_sid, prepend_zeros_to_number,
    add_anr_spacing, add_dn_spacing, add_sid_spacing,
    get_next_string, get_previous_string,
    get_next_sid, get_previous_sid, split_slice,
)
from .helpers import leaf_applier, map_to_oid, generate_garbage_filter


# --- Attribute Name Obfuscation ---

def oid_attribute_filter_obf(max_spaces=2, max_zeros=2, include_prefix=False):
    def obfuscate(attr):
        name = attr
        oid = map_to_oid(attr)
        if oid:
            name = oid
        if is_oid(name):
            if max_spaces > 0:
                name += " " * (1 + random.randint(0, max_spaces - 1))
            if max_zeros > 0:
                name = randomly_prepend_zeros_oid(name, max_zeros)
            if not name.lower().startswith("oid."):
                name = "oID." + name
        return name

    def mw(f):
        if isinstance(f, FilterEqualityMatch):
            f.attribute_desc = obfuscate(f.attribute_desc)
        elif isinstance(f, FilterSubstring):
            f.attribute_desc = obfuscate(f.attribute_desc)
        elif isinstance(f, FilterGreaterOrEqual):
            f.attribute_desc = obfuscate(f.attribute_desc)
        elif isinstance(f, FilterLessOrEqual):
            f.attribute_desc = obfuscate(f.attribute_desc)
        elif isinstance(f, FilterApproxMatch):
            f.attribute_desc = obfuscate(f.attribute_desc)
        elif isinstance(f, FilterPresent):
            f.attribute_desc = obfuscate(f.attribute_desc)
        elif isinstance(f, FilterExtensibleMatch):
            f.attribute_desc = obfuscate(f.attribute_desc)
        return f

    return leaf_applier(mw)


def anr_attribute_filter_obf(anr_set):
    def mw(f):
        if isinstance(f, FilterEqualityMatch):
            if f.attribute_desc.lower() in anr_set:
                f.attribute_desc = "aNR"
                f.assertion_value = "=" + f.assertion_value
        elif isinstance(f, FilterApproxMatch):
            if f.attribute_desc.lower() in anr_set:
                f.attribute_desc = "aNR"
                f.assertion_value = "=" + f.assertion_value
        elif isinstance(f, FilterGreaterOrEqual):
            if f.attribute_desc.lower() in anr_set:
                f.attribute_desc = "aNR"
                f.assertion_value = "=" + f.assertion_value
        elif isinstance(f, FilterLessOrEqual):
            if f.attribute_desc.lower() in anr_set:
                f.attribute_desc = "aNR"
                f.assertion_value = "=" + f.assertion_value
        return f

    return leaf_applier(mw)


# --- Garbage Obfuscation ---

def anr_substring_garbage_filter_obf(max_chars=10, garbage_charset=string.ascii_letters):
    def mw(f):
        if isinstance(f, FilterEqualityMatch) and f.attribute_desc == "aNR":
            num_garbage = 1 + random.randint(0, max_chars - 1)
            garbage = generate_garbage_string(num_garbage, garbage_charset)
            return FilterSubstring("aNR", [
                SubstringFilter(initial=f.assertion_value),
                SubstringFilter(final=garbage),
            ])
        return f

    return leaf_applier(mw)


def rand_garbage_filter_obf(max_garbage=1, garbage_size=10, charset=string.ascii_letters):
    def applier(filter_):
        if isinstance(filter_, FilterAnd):
            return FilterAnd([applier(sf) for sf in filter_.filters])
        elif isinstance(filter_, FilterOr):
            return FilterOr([applier(sf) for sf in filter_.filters])
        elif isinstance(filter_, FilterNot):
            # Never recurse into NOT - wrap with OR + garbage
            num = 1 + random.randint(0, max_garbage - 1)
            garbage_filters = [filter_] + [
                generate_garbage_filter("", garbage_size, charset) for _ in range(num)
            ]
            return FilterOr(garbage_filters)
        else:
            # Leaf node
            num = 1 + random.randint(0, max_garbage - 1)
            garbage_filters = [filter_] + [
                generate_garbage_filter("", garbage_size, charset) for _ in range(num)
            ]
            return FilterOr(garbage_filters)

    return applier


# --- Comparison Obfuscation ---

def equality_by_inclusion_filter_obf():
    def mw(filter_):
        if not isinstance(filter_, FilterEqualityMatch):
            return filter_
        token_type = get_attribute_token_format(filter_.attribute_desc)

        if token_type == TOKENSID:
            if filter_.assertion_value.count("-") <= 2:
                return filter_
            val_minus = get_previous_sid(filter_.assertion_value)
            val_plus = get_next_sid(filter_.assertion_value)
        elif token_type in NUMBER_FORMATS:
            try:
                val = int(filter_.assertion_value)
                val_minus = str(val - 1)
                val_plus = str(val + 1)
            except ValueError:
                return filter_
        elif token_type == TOKENSTRINGUNICODE:
            val_minus = get_previous_string(filter_.assertion_value)
            val_plus = get_next_string(filter_.assertion_value)
        else:
            return filter_

        return FilterAnd([
            FilterGreaterOrEqual(filter_.attribute_desc, val_minus),
            FilterLessOrEqual(filter_.attribute_desc, val_plus),
            FilterNot(FilterEqualityMatch(filter_.attribute_desc, val_minus)),
            FilterNot(FilterEqualityMatch(filter_.attribute_desc, val_plus)),
        ])

    return leaf_applier(mw)


def equality_by_exclusion_filter_obf():
    def mw(filter_):
        if not isinstance(filter_, FilterEqualityMatch):
            return filter_
        token_type = get_attribute_token_format(filter_.attribute_desc)

        if token_type == TOKENSID:
            if filter_.assertion_value.count("-") <= 2:
                return filter_
            val_minus = get_previous_sid(filter_.assertion_value)
            val_plus = get_next_sid(filter_.assertion_value)
        elif token_type in NUMBER_FORMATS:
            try:
                val = int(filter_.assertion_value)
                val_minus = str(val - 1)
                val_plus = str(val + 1)
            except ValueError:
                return filter_
        elif token_type == TOKENSTRINGUNICODE:
            val_minus = get_previous_string(filter_.assertion_value)
            val_plus = get_next_string(filter_.assertion_value)
        else:
            return filter_

        return FilterAnd([
            FilterPresent(filter_.attribute_desc),
            FilterNot(FilterLessOrEqual(filter_.attribute_desc, val_minus)),
            FilterNot(FilterGreaterOrEqual(filter_.attribute_desc, val_plus)),
        ])

    return leaf_applier(mw)


# --- Bitwise Obfuscation ---

def exact_bitwise_breakout_filter_obf():
    def mw(filter_):
        if not isinstance(filter_, FilterEqualityMatch):
            return filter_
        token_type = get_attribute_token_format(filter_.attribute_desc)
        if token_type not in NUMBER_FORMATS:
            return filter_
        try:
            val = int(filter_.assertion_value)
        except ValueError:
            return filter_

        complement = (~val) & 0xFFFFFFFF
        return FilterAnd([
            FilterExtensibleMatch("1.2.840.113556.1.4.803", filter_.attribute_desc, filter_.assertion_value),
            FilterNot(FilterExtensibleMatch("1.2.840.113556.1.4.804", filter_.attribute_desc, str(complement))),
        ])

    return leaf_applier(mw)


def bitwise_decompose_filter_obf(max_bits=31):
    def mw(filter_):
        if not isinstance(filter_, FilterExtensibleMatch):
            return filter_
        try:
            val = int(filter_.match_value)
        except ValueError:
            return filter_

        filters = []
        bits_found = 0
        remaining = val

        for i in range(31):
            if bits_found >= max_bits - 1:
                break
            if val & (1 << i):
                bit_value = 1 << i
                filters.append(FilterExtensibleMatch(
                    filter_.matching_rule, filter_.attribute_desc, str(bit_value)
                ))
                remaining &= ~bit_value
                bits_found += 1

        if remaining:
            filters.append(FilterExtensibleMatch(
                filter_.matching_rule, filter_.attribute_desc, str(remaining)
            ))

        if len(filters) > 1:
            if filter_.matching_rule == "1.2.840.113556.1.4.803":
                return FilterAnd(filters)
            elif filter_.matching_rule == "1.2.840.113556.1.4.804":
                return FilterOr(filters)
        elif len(filters) == 1:
            return filters[0]

        return filter_

    return leaf_applier(mw)


# --- Boolean Obfuscation ---

def rand_add_bool_filter_obf(max_depth=2, prob=0.5):
    def mw(f):
        depth = random.randint(1, max_depth)
        result = f
        for _ in range(depth):
            if random.random() < prob:
                if random.randint(0, 1) == 0:
                    result = FilterAnd([result])
                else:
                    result = FilterOr([result])
        return result
    return mw


def rand_dbl_neg_bool_filter_obf(max_depth=2, prob=0.5):
    def mw(f):
        depth = random.randint(1, max_depth)
        result = f
        for _ in range(depth):
            if random.random() < prob:
                result = FilterNot(FilterNot(result))
        return result
    return leaf_applier(mw)


def de_morgan_bool_filter_obf():
    def apply_de_morgan(filter_):
        if isinstance(filter_, FilterAnd):
            # a & b = !((!a) | (!b))
            not_filters = [FilterNot(apply_de_morgan(sf)) for sf in filter_.filters]
            return FilterNot(FilterOr(not_filters))
        elif isinstance(filter_, FilterOr):
            # a | b = !((!a) & (!b))
            not_filters = [FilterNot(apply_de_morgan(sf)) for sf in filter_.filters]
            return FilterNot(FilterAnd(not_filters))
        elif isinstance(filter_, FilterNot):
            return FilterNot(apply_de_morgan(filter_.filter))
        else:
            return filter_
    return apply_de_morgan


def rand_bool_reorder_filter_obf():
    def reorder(filter_):
        if isinstance(filter_, FilterAnd):
            new_filters = list(filter_.filters)
            random.shuffle(new_filters)
            return FilterAnd([reorder(sf) for sf in new_filters])
        elif isinstance(filter_, FilterOr):
            new_filters = list(filter_.filters)
            random.shuffle(new_filters)
            return FilterOr([reorder(sf) for sf in new_filters])
        elif isinstance(filter_, FilterNot):
            return FilterNot(reorder(filter_.filter))
        else:
            return filter_
    return reorder


# --- Casing Obfuscation ---

def rand_case_filter_obf(prob=0.5):
    def obfuscate(attr, val, prob_):
        token_type = get_attribute_token_format(attr)
        if token_type == TOKENSID and not val.startswith("S-"):
            return attr, val
        return randomly_change_case_string(attr, prob_), randomly_change_case_string(val, prob_)

    def mw(f):
        if isinstance(f, FilterEqualityMatch):
            f.attribute_desc, f.assertion_value = obfuscate(f.attribute_desc, f.assertion_value, prob)
        elif isinstance(f, FilterSubstring):
            f.attribute_desc = randomly_change_case_string(f.attribute_desc, prob)
            for sub in f.substrings:
                if sub.initial:
                    sub.initial = randomly_change_case_string(sub.initial, prob)
                if sub.any:
                    sub.any = randomly_change_case_string(sub.any, prob)
                if sub.final:
                    sub.final = randomly_change_case_string(sub.final, prob)
        elif isinstance(f, FilterGreaterOrEqual):
            f.attribute_desc, f.assertion_value = obfuscate(f.attribute_desc, f.assertion_value, prob)
        elif isinstance(f, FilterLessOrEqual):
            f.attribute_desc, f.assertion_value = obfuscate(f.attribute_desc, f.assertion_value, prob)
        elif isinstance(f, FilterApproxMatch):
            f.attribute_desc, f.assertion_value = obfuscate(f.attribute_desc, f.assertion_value, prob)
        elif isinstance(f, FilterPresent):
            f.attribute_desc = randomly_change_case_string(f.attribute_desc, prob)
        elif isinstance(f, FilterExtensibleMatch):
            f.attribute_desc, f.match_value = obfuscate(f.attribute_desc, f.match_value, prob)
        return f

    return leaf_applier(mw)


# --- Value Obfuscation ---

def equality_to_approx_match_filter_obf():
    def mw(f):
        if isinstance(f, FilterEqualityMatch):
            return FilterApproxMatch(f.attribute_desc, f.assertion_value)
        return f
    return leaf_applier(mw)


def rand_hex_value_filter_obf(prob=0.3):
    def apply_hex(attr, value):
        token_format = get_attribute_token_format(attr)
        if token_format == TOKENDNSTRING:
            return randomly_hex_encode_dn_string(value, prob)
        return value

    def mw(f):
        if isinstance(f, FilterEqualityMatch):
            return FilterEqualityMatch(f.attribute_desc, apply_hex(f.attribute_desc, f.assertion_value))
        elif isinstance(f, FilterApproxMatch):
            return FilterApproxMatch(f.attribute_desc, apply_hex(f.attribute_desc, f.assertion_value))
        return f

    return leaf_applier(mw)


def rand_timestamp_suffix_filter_obf(max_chars=5, charset=string.digits, use_comma=False):
    def apply_ts(value):
        return replace_timestamp(value, max_chars, charset, use_comma)

    def mw(f):
        if isinstance(f, FilterEqualityMatch):
            return FilterEqualityMatch(f.attribute_desc, apply_ts(f.assertion_value))
        elif isinstance(f, FilterGreaterOrEqual):
            return FilterGreaterOrEqual(f.attribute_desc, apply_ts(f.assertion_value))
        elif isinstance(f, FilterLessOrEqual):
            return FilterLessOrEqual(f.attribute_desc, apply_ts(f.assertion_value))
        elif isinstance(f, FilterApproxMatch):
            return FilterApproxMatch(f.attribute_desc, apply_ts(f.assertion_value))
        elif isinstance(f, FilterExtensibleMatch):
            return FilterExtensibleMatch(f.matching_rule, f.attribute_desc, apply_ts(f.match_value), f.dn_attributes)
        return f

    return leaf_applier(mw)


def rand_prepend_zeros_filter_obf(max_zeros=3):
    def prepend(attr, value):
        token_format = get_attribute_token_format(attr)
        if token_format in NUMBER_FORMATS:
            return prepend_zeros_to_number(value, max_zeros)
        elif token_format == TOKENSID:
            return prepend_zeros_to_sid(value, max_zeros)
        return value

    def mw(f):
        if isinstance(f, FilterEqualityMatch):
            return FilterEqualityMatch(f.attribute_desc, prepend(f.attribute_desc, f.assertion_value))
        elif isinstance(f, FilterGreaterOrEqual):
            return FilterGreaterOrEqual(f.attribute_desc, prepend(f.attribute_desc, f.assertion_value))
        elif isinstance(f, FilterLessOrEqual):
            return FilterLessOrEqual(f.attribute_desc, prepend(f.attribute_desc, f.assertion_value))
        elif isinstance(f, FilterApproxMatch):
            return FilterApproxMatch(f.attribute_desc, prepend(f.attribute_desc, f.assertion_value))
        elif isinstance(f, FilterExtensibleMatch):
            return FilterExtensibleMatch(f.matching_rule, f.attribute_desc, prepend(f.attribute_desc, f.match_value), f.dn_attributes)
        return f

    return leaf_applier(mw)


def rand_spacing_filter_obf(max_spaces=3):
    def mw(f):
        if isinstance(f, FilterEqualityMatch):
            token_type = get_attribute_token_format(f.attribute_desc)
            if f.attribute_desc.lower() == "anr":
                f.assertion_value = add_anr_spacing(f.assertion_value, max_spaces)
            elif token_type == TOKENDNSTRING:
                f.assertion_value = add_dn_spacing(f.assertion_value, max_spaces)
            elif token_type == TOKENSID:
                f.assertion_value = add_sid_spacing(f.assertion_value, max_spaces)
        elif isinstance(f, FilterSubstring):
            if f.attribute_desc == "aNR":
                for sub in f.substrings:
                    if sub.initial:
                        sub.initial = add_anr_spacing(sub.initial, max_spaces)
                    if sub.final:
                        sub.final = add_anr_spacing(sub.final, max_spaces)
        elif isinstance(f, FilterGreaterOrEqual):
            token_type = get_attribute_token_format(f.attribute_desc)
            if f.attribute_desc.lower() == "anr":
                f.assertion_value = add_anr_spacing(f.assertion_value, max_spaces)
            elif token_type == TOKENSID:
                f.assertion_value = add_sid_spacing(f.assertion_value, max_spaces)
        elif isinstance(f, FilterLessOrEqual):
            token_type = get_attribute_token_format(f.attribute_desc)
            if f.attribute_desc.lower() == "anr":
                f.assertion_value = add_anr_spacing(f.assertion_value, max_spaces)
            elif token_type == TOKENSID:
                f.assertion_value = add_sid_spacing(f.assertion_value, max_spaces)
        elif isinstance(f, FilterApproxMatch):
            token_type = get_attribute_token_format(f.attribute_desc)
            if f.attribute_desc.lower() == "anr":
                f.assertion_value = add_anr_spacing(f.assertion_value, max_spaces)
            elif token_type == TOKENDNSTRING:
                f.assertion_value = add_dn_spacing(f.assertion_value, max_spaces)
            elif token_type == TOKENSID:
                f.assertion_value = add_sid_spacing(f.assertion_value, max_spaces)
        return f

    return leaf_applier(mw)


def rand_substring_split_filter_obf(prob=0.3):
    def mw(filter_):
        if isinstance(filter_, FilterEqualityMatch):
            if random.random() < prob:
                token_type = get_attribute_token_format(filter_.attribute_desc)
                if token_type == TOKENSTRINGUNICODE:
                    chars = list(filter_.assertion_value)
                    split_point = random.randint(0, len(chars))
                    subs = []
                    if split_point > 0:
                        subs.append(SubstringFilter(initial="".join(chars[:split_point])))
                    if split_point < len(chars):
                        subs.append(SubstringFilter(final="".join(chars[split_point:])))
                    return FilterSubstring(filter_.attribute_desc, subs)
            return filter_

        elif isinstance(filter_, FilterSubstring):
            if random.random() < prob and filter_.substrings:
                idx = random.randint(0, len(filter_.substrings) - 1)
                sub = filter_.substrings[idx]

                if sub.initial and len(sub.initial) > 1:
                    before, after = split_slice(filter_.substrings, idx)
                    sp = random.randint(0, len(sub.initial) - 1)
                    suffix = sub.initial[sp:]
                    new_sub = SubstringFilter(initial=sub.initial[:sp])
                    filter_.substrings = before + [new_sub, SubstringFilter(any_=suffix)] + after
                elif sub.any and len(sub.any) > 1:
                    before, after = split_slice(filter_.substrings, idx)
                    sp = random.randint(1, len(sub.any) - 1)
                    suffix = sub.any[sp:]
                    new_sub = SubstringFilter(any_=sub.any[:sp])
                    filter_.substrings = before + [new_sub, SubstringFilter(any_=suffix)] + after
                elif sub.final and len(sub.final) > 1:
                    before, after = split_slice(filter_.substrings, idx)
                    sp = random.randint(1, len(sub.final))
                    prefix = sub.final[:sp]
                    new_sub = SubstringFilter(final=sub.final[sp:])
                    filter_.substrings = before + [SubstringFilter(any_=prefix), new_sub] + after
            return filter_

        return filter_

    return leaf_applier(mw)


def equality_to_extensible_filter_obf(dn=False):
    def mw(f):
        if isinstance(f, FilterEqualityMatch):
            return FilterExtensibleMatch("", f.attribute_desc, f.assertion_value, dn)
        return f
    return leaf_applier(mw)


def replace_tautologies_filter_obf():
    greedy_presences = [
        "objectclass", "distinguishedname", "name", "objectguid",
        "objectcategory", "whencreated", "whenchanged", "usncreated", "usnchanged",
    ]

    existing_attrs = list(ATTR_CONTEXTS.keys())

    def make_basic_tautology(filter_):
        return FilterOr([FilterNot(filter_), filter_])

    def random_bitwise_tautology_and(_):
        attr = random.choice(BITWISE_ATTRS)
        return FilterOr([
            FilterExtensibleMatch("1.2.840.113556.1.4.803", attr, "0"),
            FilterNot(FilterPresent(attr)),
        ])

    def random_bitwise_tautology_or(_):
        attr = random.choice(BITWISE_ATTRS)
        return FilterOr([
            FilterExtensibleMatch("1.2.840.113556.1.4.804", attr, "4294967295"),
            FilterNot(FilterPresent(attr)),
            FilterEqualityMatch(attr, "0"),
        ])

    def random_typo_tautology(_):
        for _ in range(100):
            attr = random.choice(existing_attrs)
            runes = list(attr)
            idx = random.randint(0, len(runes) - 1)
            if random.randint(0, 1) == 0:
                runes[idx] = chr(random.randint(ord("a"), ord("z")))
            else:
                runes[idx] = chr(random.randint(ord("A"), ord("Z")))
            typo = "".join(runes)
            if typo.lower() not in ATTR_CONTEXTS:
                return FilterNot(FilterPresent(typo))
        return FilterNot(FilterPresent("xXxNonExistentxXx"))

    def random_presence_tautology(filter_):
        current_attr = get_attr_name(filter_)
        attr = ""
        for _ in range(100):
            attr = random.choice(existing_attrs)
            if attr != current_attr:
                break
        return make_basic_tautology(FilterPresent(attr))

    def random_equality_tautology(filter_):
        current_attr = get_attr_name(filter_)
        attr = ""
        for _ in range(100):
            attr = random.choice(existing_attrs)
            if attr != current_attr:
                break
        return make_basic_tautology(FilterEqualityMatch(attr, chr(random.randint(ord("a"), ord("z")))))

    def random_substring_tautology(filter_):
        current_attr = get_attr_name(filter_)
        attr = ""
        for _ in range(100):
            attr = random.choice(existing_attrs)
            if attr != current_attr:
                break
        subs = []
        if random.randint(0, 1) == 0:
            subs.append(SubstringFilter(initial=chr(random.randint(ord("a"), ord("z")))))
        if random.randint(0, 1) == 0:
            subs.append(SubstringFilter(any_=chr(random.randint(ord("a"), ord("z")))))
        if random.randint(0, 1) == 0:
            subs.append(SubstringFilter(final=chr(random.randint(ord("a"), ord("z")))))
        return make_basic_tautology(FilterSubstring(attr, subs))

    def random_bitwise_tautology(filter_):
        attr = random.choice(BITWISE_ATTRS)
        rule = random.choice(["1.2.840.113556.1.4.803", "1.2.840.113556.1.4.804"])
        return make_basic_tautology(FilterExtensibleMatch(rule, attr, str(random.randint(0, 4294967295))))

    tautologies = [
        random_bitwise_tautology_and,
        random_bitwise_tautology_or,
        random_typo_tautology,
        random_presence_tautology,
        random_equality_tautology,
        random_substring_tautology,
        random_bitwise_tautology,
    ]

    def mw(f):
        if isinstance(f, FilterPresent):
            if f.attribute_desc.lower() in greedy_presences:
                return random.choice(tautologies)(f)
        return f

    return leaf_applier(mw)
