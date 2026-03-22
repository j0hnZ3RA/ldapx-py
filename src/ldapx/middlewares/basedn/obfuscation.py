"""
BaseDN obfuscation middlewares - Python port of ldapx middlewares/basedn/obfuscation.go
"""

import random

from ldapx.parser.consts import OIDS_MAP
from ldapx.parser.validation import is_oid
from ldapx.middlewares.helpers.string import (
    randomly_change_case_string, randomly_prepend_zeros_oid,
    randomly_hex_encode_string,
)


def rand_case_basedn_obf(prob=0.5):
    def mw(dn):
        return randomly_change_case_string(dn, prob)
    return mw


def oid_attribute_basedn_obf(max_spaces=2, max_zeros=2, include_prefix=False):
    def mw(dn):
        parts = dn.split(",")
        for i, part in enumerate(parts):
            kv = part.split("=", 1)
            if len(kv) == 2:
                attr_name = kv[0].strip()
                oid = OIDS_MAP.get(attr_name.lower())
                if oid:
                    attr_name = oid
                if is_oid(attr_name):
                    if max_spaces > 0:
                        attr_name += " " * (1 + random.randint(0, max_spaces - 1))
                    if max_zeros > 0:
                        attr_name = randomly_prepend_zeros_oid(attr_name, max_zeros)
                    if not attr_name.lower().startswith("oid."):
                        attr_name = "oID." + attr_name
                parts[i] = attr_name + "=" + kv[1]
        return ",".join(parts)
    return mw


def rand_spacing_basedn_obf(max_spaces=2):
    def mw(dn):
        if not dn or max_spaces <= 0:
            return dn
        sp1 = " " * (1 + random.randint(0, max_spaces - 1))
        sp2 = " " * (1 + random.randint(0, max_spaces - 1))
        r = random.randint(0, 2)
        if r == 0:
            return dn + sp1
        elif r == 1:
            return sp1 + dn
        else:
            return sp1 + dn + sp2
    return mw


def double_quotes_basedn_obf():
    def mw(dn):
        parts = dn.split(",")
        for i, part in enumerate(parts):
            kv = part.split("=", 1)
            if len(kv) == 2:
                value = kv[1]
                if "\\" in value:
                    continue
                if i == len(parts) - 1 and value.endswith(" "):
                    trimmed = value.rstrip(" ")
                    trailing = " " * (len(value) - len(trimmed))
                    parts[i] = kv[0] + '="' + trimmed + '"' + trailing
                else:
                    parts[i] = kv[0] + '="' + value + '"'
        return ",".join(parts)
    return mw


def guid_basedn_obf(guid_hex):
    """Replace the BaseDN with the <GUID=hex> alternative form.

    Per MS-ADTS 3.1.1.3.1.2.4, AD supports alternative DN forms including
    <GUID=object_guid> where object_guid is the hex representation of the
    objectGUID attribute. This completely changes the BaseDN format, making
    it unrecognizable as a traditional DN.

    The guid_hex parameter should be the hex string of the objectGUID
    (e.g., "f1f089baf8d27c488e938079cdb3b551"). Use resolve_basedn_guid()
    helper to obtain it from an LDAP connection.

    Works with any LDAP library (ldap3, badldap, etc.) — no DN parser issues.
    """
    def mw(dn):
        if not dn or not guid_hex:
            return dn
        return "<GUID=%s>" % guid_hex
    return mw


def sid_basedn_obf(sid):
    """Replace the BaseDN with the <SID=sid> alternative form.

    Per MS-ADTS 3.1.1.3.1.2.4, AD supports <SID=sid> where sid is either
    the string form (S-1-5-21-...) or hex representation of the binary SID.
    This completely changes the BaseDN format.

    The sid parameter should be a SID string (e.g., "S-1-5-21-677041200-...")
    or hex string. Use resolve_basedn_sid() helper to obtain it.

    Works with any LDAP library (ldap3, badldap, etc.) — no DN parser issues.
    """
    def mw(dn):
        if not dn or not sid:
            return dn
        return "<SID=%s>" % sid
    return mw


# Well-Known GUIDs for standard AD containers (fixed across all AD installations)
# Per MS-ADTS 3.1.1.3.1.2.4
_WKGUIDS = {
    "cn=users,": "a9d1ca15768811d1aded00c04fd8d5cd",
    "cn=computers,": "aa312825768811d1aded00c04fd8d5cd",
    "cn=system,": "ab1d30f3768811d1aded00c04fd8d5cd",
    "cn=domain controllers,": "a361b2ffffd211d1aa4b00c04fd7d83a",
    "cn=infrastructure,": "2fbac1870ade11d297c400c04fd8d5cd",
    "cn=deleted objects,": "18e2ea80684f11d2b9aa00c04f79f805",
    "cn=lostandfound,": "ab8153b7768811d1aded00c04fd8d5cd",
}


def wkguid_basedn_obf():
    """Replace BaseDN with <WKGUID=guid,domain_dn> when it matches a well-known container.

    Per MS-ADTS 3.1.1.3.1.2.4, AD supports the <WKGUID=guid,object_DN> format
    for referencing well-known containers like Users, Computers, System, etc.
    These GUIDs are fixed across all AD installations, so no pre-query is needed.

    If the BaseDN starts with a well-known container (e.g., CN=Users,DC=corp,...),
    it is replaced with <WKGUID=guid,DC=corp,...>. If the BaseDN is a domain root
    or doesn't match a well-known container, it is returned unchanged.
    """
    def mw(dn):
        if not dn:
            return dn
        dn_lower = dn.lower()
        for prefix, guid in _WKGUIDS.items():
            if dn_lower.startswith(prefix):
                # Extract the domain DN part (everything after the container CN)
                domain_dn = dn[len(prefix):]
                return "<WKGUID=%s,%s>" % (guid, domain_dn)
        return dn
    return mw


def rand_hex_value_basedn_obf(prob=0.3):
    def mw(dn):
        parts = dn.split(",")
        for i, part in enumerate(parts):
            kv = part.split("=", 1)
            if len(kv) == 2:
                value = kv[1]
                if value and (value[0] == '"' or value[-1] == '"'):
                    continue
                spaces = ""
                if value.endswith(" "):
                    trimmed = value.rstrip(" ")
                    spaces = " " * (len(value) - len(trimmed))
                    value = trimmed
                kv[1] = randomly_hex_encode_string(value, prob) + spaces
                parts[i] = kv[0] + "=" + kv[1]
        return ",".join(parts)
    return mw
