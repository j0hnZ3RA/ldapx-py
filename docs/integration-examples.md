# Integration Examples

Step-by-step examples for integrating ldapx into popular security tools. Each example shows exactly which file to modify and what code to add.

## impacket (GetADUsers, GetUserSPNs, NetExec, etc.)

impacket uses its own LDAP implementation. All queries go through `LDAPConnection.search()` in `impacket/ldap/ldap.py`.

**File to modify:** `impacket/ldap/ldap.py`

Find the `search` method (around line 479):

```python
def search(self, searchBase=None, scope=None, derefAliases=None, sizeLimit=0, timeLimit=0, typesOnly=False,
           searchFilter='(objectClass=*)', attributes=None, searchControls=None, perRecordCallback=None):

    if not isinstance(searchFilter, six.text_type):
        raise LDAPFilterInvalidException(...)

    if searchBase is None:
        searchBase = self._baseDN
```

Add the ldapx block **after** the `isinstance` check and **before** `if searchBase is None`:

```python
    if not isinstance(searchFilter, six.text_type):
        raise LDAPFilterInvalidException(...)

    # --- ldapx obfuscation ---
    _ldapx_filter = getattr(self, '_ldapx_filter', '')
    _ldapx_basedn = getattr(self, '_ldapx_basedn', '')
    if _ldapx_filter or _ldapx_basedn:
        try:
            import ldapx, logging
            if _ldapx_filter and searchFilter:
                orig = searchFilter
                searchFilter = ldapx.obfuscate_filter(searchFilter, _ldapx_filter)
                logging.debug("[ldapx] Filter: %s -> %s", orig, searchFilter)
            if _ldapx_basedn and searchBase:
                orig = searchBase
                searchBase = ldapx.obfuscate_basedn(searchBase, _ldapx_basedn)
                logging.debug("[ldapx] BaseDN: %s -> %s", orig, searchBase)
        except ImportError:
            pass
    # --- end ldapx ---

    if searchBase is None:
        searchBase = self._baseDN
```

**Activate it** — after creating the connection, set the chains:

```python
from impacket.ldap import ldap as ldap_impacket

conn = ldap_impacket.LDAPConnection('ldap://dc_ip', baseDN, dc_ip)
conn.login(username, password, domain)

# Enable ldapx
conn._ldapx_filter = "CDR"   # Case + DblNeg + Reorder
conn._ldapx_basedn = "C"     # Case
```

**Supported codes:** All filter codes except `O` (OID). All BaseDN codes.

---

## Certipy (ldap3-based)

Certipy uses ldap3. Requires a monkey-patch on ldap3's attribute validator for garbage/OID filter codes.

**File to modify:** `certipy/lib/ldap.py`

Find the `search` method in the `LDAPConnection` class (around line 1005):

```python
def search(self, search_filter, attributes=..., search_base=None, query_sd=False, **kwargs):
    if search_base is None:
        search_base = self.default_path
```

Add the ldapx block **after** `search_base = self.default_path`:

```python
    if search_base is None:
        search_base = self.default_path

    # --- ldapx obfuscation ---
    _ldapx_filter = getattr(self, '_ldapx_filter', '')
    _ldapx_basedn = getattr(self, '_ldapx_basedn', '')
    if _ldapx_filter or _ldapx_basedn:
        try:
            import ldapx as _ldapx
            if _ldapx_filter and search_filter:
                search_filter = _ldapx.obfuscate_filter(search_filter, _ldapx_filter)
            if _ldapx_basedn and search_base:
                search_base = _ldapx.obfuscate_basedn(search_base, _ldapx_basedn)
        except ImportError:
            pass
    # --- end ldapx ---
```

**Monkey-patch ldap3 validator** — add this in the `__init__` of `LDAPConnection` (around line 554):

```python
# --- ldapx: patch ldap3 validator to accept obfuscated attr names ---
try:
    import ldap3.protocol.convert as _convert
    if not getattr(_convert, '_ldapx_patched', False):
        _orig_validate = _convert.validate_attribute_value
        def _permissive_validate(schema, name, value, auto_encode=False, validator=None, check_names=False):
            try:
                return _orig_validate(schema, name, value, auto_encode, validator, check_names)
            except Exception:
                return value.encode('utf-8') if isinstance(value, str) else value
        _convert.validate_attribute_value = _permissive_validate
        _convert._ldapx_patched = True
except Exception:
    pass
# --- end ldapx ---
```

**Activate it** — set the chains on the LDAPConnection instance:

```python
ldap_conn = LDAPConnection(target)
ldap_conn._ldapx_filter = "CDR"
ldap_conn._ldapx_basedn = "C"
```

**Supported codes:** All filter codes (with monkey-patch). BaseDN: C, X, U, I (not S, Q, O).

---

## bloodhound.py (ldap3-based)

bloodhound.py uses ldap3. All queries go through `ADDC.search()` in `bloodhound/ad/domain.py`.

**File to modify:** `bloodhound/ad/domain.py`

1. Add the ldap3 validator monkey-patch (same as Certipy above) as a module-level function:

```python
def _patch_ldap3_for_ldapx():
    try:
        import ldap3.protocol.convert as _convert
        _orig = _convert.validate_attribute_value
        def _permissive(schema, name, value, auto_encode=False, validator=None, check_names=False):
            try:
                return _orig(schema, name, value, auto_encode, validator, check_names)
            except Exception:
                return value.encode('utf-8') if isinstance(value, str) else value
        _convert.validate_attribute_value = _permissive
    except Exception:
        pass
```

2. In `ADDC.search()`, add obfuscation before the `paged_search` call:

```python
    # --- ldapx obfuscation ---
    if any((self.ad.ldapx_filter, self.ad.ldapx_basedn, self.ad.ldapx_attrs)):
        try:
            import ldapx
            if self.ad.ldapx_filter and search_filter:
                search_filter = ldapx.obfuscate_filter(search_filter, self.ad.ldapx_filter)
            if self.ad.ldapx_basedn and search_base:
                search_base = ldapx.obfuscate_basedn(search_base, self.ad.ldapx_basedn)
            if self.ad.ldapx_attrs and attributes and attributes != ALL_ATTRIBUTES:
                attributes = ldapx.obfuscate_attrlist(list(attributes), self.ad.ldapx_attrs)
        except ImportError:
            pass
    # --- end ldapx ---
```

3. Add `ldapx_filter`, `ldapx_basedn`, `ldapx_attrs` parameters to the `AD` class `__init__`.

4. Add CLI flags `--ldapx-filter`, `--ldapx-basedn`, `--ldapx-attrs` in `bloodhound/__init__.py`.

**Supported codes:** All filter codes (with monkey-patch). BaseDN: C, X, U, I.

---

## bloodyAD (badldap-based)

bloodyAD uses badldap, which has a PEG parser that can't handle obfuscated filter syntax. The solution is to use the ldapx ASN1 adapter to bypass the parser entirely.

**File to create:** `bloodyAD/network/ldapx_integration.py`

```python
import logging
from ldapx import obfuscate_basedn, obfuscate_attrlist, obfuscate_attrentries
from ldapx.parser import query_to_filter
from ldapx.adapters.badldap import ast_to_asn1
import ldapx as _ldapx

LOG = logging.getLogger(__name__)

def apply_filter_obfuscation(filter_str, chain):
    """Returns ASN1 Filter object (not string) for badldap compatibility."""
    if not filter_str or not chain:
        return filter_str
    try:
        f = query_to_filter(filter_str)
    except Exception as e:
        LOG.warning("Failed to parse filter: %s", e)
        return filter_str

    middlewares = _ldapx._build_filter_middlewares()
    for code in chain:
        factory = middlewares.get(code)
        if factory:
            f = factory()(f)

    try:
        return ast_to_asn1(f)
    except Exception as e:
        LOG.warning("Failed ASN1 conversion: %s", e)
        return filter_str

def apply_basedn_obfuscation(basedn, chain):
    return obfuscate_basedn(basedn, chain)

def apply_attrlist_obfuscation(attrs, chain):
    return obfuscate_attrlist(attrs, chain)

def apply_attrentries_obfuscation(entries, chain):
    return obfuscate_attrentries(entries, chain)
```

**File to modify:** `bloodyAD/network/ldap.py` — change the import:

```python
# Replace:
from bloodyAD.network.ldapx import (...)
# With:
from bloodyAD.network.ldapx_integration import (...)
```

Also add the badldap monkey-patch at module level in `ldap.py`:

```python
import badldap.connection as _badldap_connection
from badldap.protocol.messages import Filter as _ASN1Filter

_original_qsc = _badldap_connection.query_syntax_converter
def _patched_query_syntax_converter(query):
    if isinstance(query, _ASN1Filter):
        return query
    return _original_qsc(query)
_badldap_connection.query_syntax_converter = _patched_query_syntax_converter
```

**Supported codes:** All filter codes (all 22). All BaseDN codes. All AttrList codes except W/w/p/e.

---

## Obtaining GUID/SID for BaseDN codes U and I

The `U` (GUID) and `I` (SID) BaseDN codes require the objectGUID or objectSid of the base object. These must be obtained via a query before enabling obfuscation. AD accepts both hex and dashed GUID formats.

### ldap3 (bloodhound.py, Certipy)

```python
import ldap3

conn.search(base_dn, '(objectClass=*)', search_scope=ldap3.BASE,
            attributes=['objectGUID', 'objectSid'])

guid_hex = conn.response[0]['raw_attributes']['objectGUID'][0].hex()
sid_str = str(conn.entries[0].objectSid)

import ldapx
opts = ldapx.Options(BaseDNGuid=guid_hex, BaseDNSid=sid_str)
```

### impacket (GetADUsers, NetExec)

```python
from impacket.ldap import ldapasn1 as ldapasn1_impacket

resp = conn.search(searchBase=base_dn, searchFilter='(objectClass=domain)',
                   attributes=['objectGUID', 'objectSid'])

for item in resp:
    if isinstance(item, ldapasn1_impacket.SearchResultEntry):
        for attr in item['attributes']:
            if str(attr['type']) == 'objectGUID':
                guid_hex = bytes(attr['vals'][0]).hex()
            elif str(attr['type']) == 'objectSid':
                from impacket.ldap.ldaptypes import LDAP_SID
                sid_str = LDAP_SID(data=bytes(attr['vals'][0])).formatCanonical()

import ldapx
opts = ldapx.Options(BaseDNGuid=guid_hex, BaseDNSid=sid_str)
```

### badldap (bloodyAD)

badldap returns GUID as dashed string and SID as string, both usable directly:

```python
async for entry, err in client.pagedsearch(
    '(objectClass=domain)', ['objectGUID', 'objectSid']):
    guid_dashed = entry['attributes']['objectGUID']  # "ba89f0f1-d2f8-487c-..."
    sid_str = entry['attributes']['objectSid']        # "S-1-5-21-..."

import ldapx
opts = ldapx.Options(BaseDNGuid=guid_dashed, BaseDNSid=sid_str)
```

## General pattern

For any Python tool that uses LDAP, the integration pattern is:

1. Find the central `search()` method
2. Add `ldapx.obfuscate_filter()` and `ldapx.obfuscate_basedn()` before the query is sent
3. If the tool uses ldap3: add the validator monkey-patch
4. If the tool uses badldap: use the ASN1 adapter instead of string output
5. If the tool uses impacket: works natively (no monkey-patch needed, except for OID code)
