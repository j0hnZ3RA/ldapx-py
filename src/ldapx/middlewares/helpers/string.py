"""
String manipulation helpers - Python port of ldapx middlewares/helpers/string.go
and middlewares/filter/helpers.go
"""

import random
import re
import string


def generate_garbage_string(n, chars=string.ascii_letters + string.digits):
    return "".join(random.choice(chars) for _ in range(n))


def hex_encode_char(c):
    return "\\%02x" % ord(c)


def randomly_hex_encode_string(s, prob):
    result = []
    for c in s:
        if random.random() < prob:
            result.append(hex_encode_char(c))
        else:
            result.append(c)
    return "".join(result)


def randomly_change_case_string(s, prob):
    result = []
    for c in s:
        if random.random() < prob:
            if random.randint(0, 1) == 0:
                result.append(c.lower())
            else:
                result.append(c.upper())
        else:
            result.append(c)
    return "".join(result)


def randomly_prepend_zeros_oid(oid, max_zeros):
    parts = oid.split(".")
    for j, part in enumerate(parts):
        if part.lower() != "oid":
            zeros = "0" * (1 + random.randint(0, max_zeros - 1))
            parts[j] = zeros + part
    return ".".join(parts)


# --- Filter helpers ---

def randomly_hex_encode_dn_string(dn_string, prob):
    parts = dn_string.split(",")
    for i, part in enumerate(parts):
        kv = part.split("=", 1)
        if len(kv) == 2:
            encoded_value = randomly_hex_encode_string(kv[1], prob)
            parts[i] = kv[0] + "=" + encoded_value
    return ",".join(parts)


def replace_timestamp(value, max_chars, charset, use_comma):
    pattern = re.compile(r"^([0-9]{14})[.,](.*)(Z|[+-].{4})(.*)")
    m = pattern.match(value)
    if not m:
        return value

    parts = m.groups()
    rand_str1 = generate_garbage_string(max_chars, charset)
    rand_str2 = generate_garbage_string(max_chars, charset)

    prepend = ""
    append = ""
    r = random.randint(0, 2)
    if r == 0:
        prepend = rand_str1
    elif r == 1:
        append = rand_str2
    else:
        prepend = rand_str1
        append = rand_str2

    sep = "," if use_comma else "."
    return "%s%s%s%s%s%s%s" % (parts[0], sep, parts[1], prepend, parts[2], append, parts[3])


def prepend_zeros_to_sid(sid, max_zeros):
    parts = sid.split("-")
    for i in range(1, len(parts)):
        num_zeros = random.randint(0, max_zeros - 1)
        if num_zeros > 0:
            zeros = "0" * num_zeros
            # Find first digit
            for j, c in enumerate(parts[i]):
                if c.isdigit():
                    parts[i] = parts[i][:j] + zeros + parts[i][j:]
                    break
    return "-".join(parts)


def prepend_zeros_to_number(value, max_zeros):
    num_zeros = random.randint(0, max_zeros - 1)
    zeros = "0" * num_zeros
    if value and value[0] == "-":
        return "-" + zeros + value[1:]
    return zeros + value


def add_anr_spacing(value, max_spaces):
    spaces_fst = " " * (1 + random.randint(0, max_spaces - 1))
    spaces_eq = " " * (1 + random.randint(0, max_spaces - 1))
    spaces_lst = " " * (1 + random.randint(0, max_spaces - 1))

    trimmed = value.lstrip()
    if trimmed.startswith("="):
        idx = value.index("=")
        if idx + 1 < len(value) and random.random() < 0.5:
            value = value[:idx+1] + spaces_eq + value[idx+1:]

    r = random.randint(0, 2)
    if r == 0:
        return spaces_fst + value
    elif r == 1:
        return value + spaces_lst
    else:
        return spaces_fst + value + spaces_lst


def add_dn_spacing(value, max_spaces):
    parts = value.split(",")
    for i, part in enumerate(parts):
        kv = part.split("=", 1)
        if len(kv) == 2:
            r = random.randint(0, 3)
            sp = " " * (1 + random.randint(0, max_spaces - 1))
            if r == 0:
                kv[0] = kv[0] + sp
            elif r == 1:
                kv[1] = sp + kv[1]
            elif r == 2:
                kv[0] = sp + kv[0]
            else:
                kv[1] = kv[1] + sp
            parts[i] = "=".join(kv)
    return ",".join(parts)


def add_sid_spacing(sid, max_spaces):
    parts = sid.split("-")
    if len(parts) >= 3:
        sp1 = " " * random.randint(0, max_spaces)
        sp2 = " " * random.randint(0, max_spaces)
        parts[1] = sp1 + parts[1]
        parts[2] = sp2 + parts[2]
    return "-".join(parts)


# Comparison helpers

CHAR_ORDERING = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"


def get_next_string(s):
    chars = list(s)
    for i in range(len(chars) - 1, -1, -1):
        pos = CHAR_ORDERING.find(chars[i])
        if pos < len(CHAR_ORDERING) - 1:
            chars[i] = CHAR_ORDERING[pos + 1]
            return "".join(chars)
        chars[i] = CHAR_ORDERING[0]
    return s + CHAR_ORDERING[0]


def get_previous_string(s):
    chars = list(s)
    for i in range(len(chars) - 1, -1, -1):
        pos = CHAR_ORDERING.find(chars[i])
        if pos > 0:
            chars[i] = CHAR_ORDERING[pos - 1]
            return "".join(chars)
        chars[i] = CHAR_ORDERING[-1]
    if len(s) > 1:
        return s[:-1]
    return s


def get_next_sid(sid):
    parts = sid.split("-")
    if not parts:
        return sid
    try:
        num = int(parts[-1])
        parts[-1] = str(num + 1)
    except ValueError:
        pass
    return "-".join(parts)


def get_previous_sid(sid):
    parts = sid.split("-")
    if not parts:
        return sid
    try:
        num = int(parts[-1])
        if num > 0:
            parts[-1] = str(num - 1)
    except ValueError:
        pass
    return "-".join(parts)


def split_slice(lst, idx):
    return lst[:idx], lst[idx+1:]
