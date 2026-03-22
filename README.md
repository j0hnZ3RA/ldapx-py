# ldapx

[![PyPI version](https://img.shields.io/pypi/v/ldapx)](https://pypi.org/project/ldapx/)
[![Python versions](https://img.shields.io/pypi/pyversions/ldapx)](https://pypi.org/project/ldapx/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Python port of [ldapx](https://github.com/Macmod/ldapx) - LDAP query obfuscation library.

Transform LDAP filters, BaseDNs, attribute lists, and attribute entries using composable middleware chains. Zero dependencies. Works as a library or CLI tool.

## Installation

```bash
pip install ldapx
```

## Quick Start

```python
import ldapx

# Obfuscate a filter with case mutation + OID attributes
result = ldapx.obfuscate_filter("(cn=admin)", "CO")
# → (oID.02.05.04.03 =aDmIn)

# Obfuscate a BaseDN
result = ldapx.obfuscate_basedn("DC=corp,DC=local", "COQ")
# → oID.0.9.2342.19200300.100.1.25 ="cOrP",oID.0.9.2342.19200300.100.1.25 ="lOcAl"

# Obfuscate an attribute list
result = ldapx.obfuscate_attrlist(["cn", "sAMAccountName"], "COR")
# → ['oID.1.2.840.113556.1.4.221 ', 'oID.02.5.4.3  ']
```

## Usage Patterns

### Pattern 1: High-level chain strings (simplest)

```python
import ldapx

result = ldapx.obfuscate_filter("(sAMAccountName=user1)", "COGDR")
result = ldapx.obfuscate_basedn("DC=corp,DC=local", "CSQOX")
result = ldapx.obfuscate_attrlist(["cn", "sAMAccountName"], "CRDG")
result = ldapx.obfuscate_attrentries({"cn": [b"test"]}, "CR")
```

### Pattern 2: Explicit chain (Go-style)

```python
from ldapx.parser import query_to_filter, filter_to_query
from ldapx.middlewares.filter import (
    FilterMiddlewareChain,
    rand_case_filter_obf,
    oid_attribute_filter_obf,
)

chain = FilterMiddlewareChain()
chain.add("Case", lambda: rand_case_filter_obf(0.7))
chain.add("OID", lambda: oid_attribute_filter_obf(4, 4))

f = query_to_filter("(cn=admin)")
f = chain.execute(f, verbose=True)
result = filter_to_query(f)
```

### Pattern 3: Direct composition

```python
from ldapx.parser import query_to_filter, filter_to_query
from ldapx.middlewares.filter import rand_case_filter_obf, oid_attribute_filter_obf

f = query_to_filter("(cn=admin)")
f = rand_case_filter_obf(0.5)(f)
f = oid_attribute_filter_obf(2, 2)(f)
result = filter_to_query(f)
```

## CLI

```bash
# Obfuscate a filter
ldapx filter -f "(cn=admin)" -c "COGDR"

# Generate 5 variants
ldapx filter -f "(cn=admin)" -c "COGDR" -n 5

# Obfuscate a BaseDN
ldapx basedn -b "DC=corp,DC=local" -c "CSQOX"

# Obfuscate attribute list
ldapx attrlist -a "cn,sAMAccountName,memberOf" -c "CRDG"

# List available codes
ldapx codes --all

# Pipe from stdin
echo "(cn=admin)" | ldapx filter -c "COGDR"

# JSON output
ldapx filter -f "(cn=admin)" -c "CO" --json

# Custom options
ldapx filter -f "(cn=admin)" -c "CO" -o FiltCaseProb=0.8 -o FiltOIDMaxSpaces=4
```

## Middleware Codes

### Filter (`-f`)

| Code | Name | Description |
|------|------|-------------|
| `C` | Random case | Randomize case of attribute names and values |
| `S` | Random spacing | Add context-aware spacing (ANR, DN, SID) |
| `G` | Garbage filters | Wrap filters in OR with random garbage |
| `T` | Replace tautologies | Replace simple presence filters with tautologies |
| `R` | Boolean reorder | Randomly shuffle AND/OR clauses |
| `O` | OID attributes | Replace attribute names with OIDs |
| `X` | Hex value encoding | Hex-encode characters in DN-type values |
| `t` | Timestamp garbage | Add garbage to timestamp patterns |
| `B` | Add random boolean | Wrap with redundant AND/OR |
| `D` | Double negation | Apply `(!(!(filter)))` |
| `M` | DeMorgan transform | Apply De Morgan's laws |
| `b` | Bitwise breakout | Convert equality to bitwise matching rules |
| `d` | Bitwise decompose | Break bitwise values into individual bits |
| `I` | Equality by inclusion | `(attr=val)` to range + exclusion |
| `E` | Equality by exclusion | `(attr=val)` to presence + NOT range |
| `A` | Approx match | `(attr=val)` to `(attr~=val)` |
| `x` | Extensible match | `(attr=val)` to `(attr:=val)` |
| `Z` | Prepend zeros | Add leading zeros to numbers/SIDs |
| `s` | Substring split | Split equality into substring match |
| `N` | Names to ANR | Replace ANR-set attributes with `aNR` |
| `n` | ANR garbage | Add garbage to ANR substring queries |
| `P` | dnAttributes noise | Randomly toggle `:dn:` on extensible match (AD ignores it, [MS-ADTS 3.1.1.3.1.3.1]) |
| `L` | Transitive eval | Convert link attr equality to `LDAP_MATCHING_RULE_TRANSITIVE_EVAL` (1941) |

### BaseDN (`-b`)

| Code | Name | Description |
|------|------|-------------|
| `C` | Random case | Randomize case |
| `S` | Random spacing | Add spaces around DN |
| `Q` | Double quotes | Wrap DN values in quotes |
| `O` | OID attributes | Replace DN attr names with OIDs |
| `X` | Hex value encoding | Hex-encode DN value characters |
| `U` | GUID format | Replace DN with `<GUID=hex>` ([MS-ADTS 3.1.1.3.1.2.4]). Requires `-o BaseDNGuid=hex` |
| `I` | SID format | Replace DN with `<SID=string>` ([MS-ADTS 3.1.1.3.1.2.4]). Requires `-o BaseDNSid=S-1-...` |

### AttrList (`-a`)

| Code | Name | Description |
|------|------|-------------|
| `C` | Random case | Randomize case |
| `R` | Reorder list | Shuffle attribute order |
| `D` | Duplicate | Add duplicate entries |
| `O` | OID attributes | Replace with OIDs |
| `G` | Garbage (non-existing) | Add random fake attributes |
| `g` | Garbage (existing) | Add random real attributes |
| `W` | Replace with wildcard | Replace list with `*` |
| `w` | Add wildcard | Append `*` to list |
| `p` | Add plus | Append `+` (operational attrs) |
| `e` | Replace with empty | Replace with empty list |

### AttrEntries

| Code | Name | Description |
|------|------|-------------|
| `C` | Random case | Randomize attribute name case |
| `R` | Reorder list | Shuffle attribute order |
| `O` | OID attributes | Replace with plain OIDs |

## Options

Customize middleware parameters via `Options`:

```python
import ldapx

opts = ldapx.Options(
    FiltCaseProb=0.8,           # Higher case mutation probability
    FiltOIDMaxSpaces=4,         # More spaces after OIDs
    FiltGarbageMaxElems=3,      # More garbage filters
    BDNSpacingMaxSpaces=4,      # More spacing in BaseDN
)

result = ldapx.obfuscate_filter("(cn=admin)", "COGDR", options=opts)
```

## Adapters

The core library has zero dependencies and returns strings. For integration with specific LDAP libraries, use adapters:

### badldap adapter

```python
# pip install ldapx[badldap]
from ldapx.parser import query_to_filter
from ldapx.middlewares.filter import rand_case_filter_obf
from ldapx.adapters.badldap import ast_to_asn1

f = query_to_filter("(cn=admin)")
f = rand_case_filter_obf(0.5)(f)
asn1_filter = ast_to_asn1(f)  # badldap ASN1 Filter object
```

## Compatibility Matrix

Active Directory accepts all obfuscation formats — the server-side parser is very permissive. However, each LDAP library has its own **client-side parser** that validates filters and DNs **before** sending them to the server. If the client rejects the obfuscated query, it never reaches AD. This is why compatibility varies by library, and why some codes require workarounds (monkey-patching the client validator or using an ASN1 adapter to bypass the client parser entirely).

Below is a full compatibility matrix tested against a real Active Directory environment.

### Filter codes

| Code | Name | badldap | impacket | ldap3 | Notes |
|------|------|---------|----------|-------|-------|
| `C` | Case | via adapter | native | native | |
| `S` | Spacing | via adapter | native | native | |
| `G` | Garbage | via adapter | native | monkey-patch | ldap3 rejects unknown attr names |
| `T` | Tautologies | via adapter | native | native | |
| `R` | Reorder | via adapter | native | native | |
| `O` | OID | via adapter | **FAIL** | monkey-patch | impacket/ldap3 reject `oID.` format |
| `X` | Hex value | via adapter | native | native | |
| `t` | Timestamp | via adapter | native | native | |
| `B` | AddBool | via adapter | native | native | |
| `D` | DblNeg | via adapter | native | native | |
| `M` | DeMorgan | via adapter | native | native | |
| `b` | Bitwise | via adapter | native | native | |
| `d` | Decompose | via adapter | native | native | |
| `I` | Inclusion | via adapter | native | native | |
| `E` | Exclusion | via adapter | native | native | |
| `A` | Approx | via adapter | native | native | |
| `x` | Extensible | via adapter | native | native | |
| `Z` | Zeros | via adapter | native | native | |
| `s` | Substring | via adapter | native | native | |
| `N` | ANR | via adapter | native | native | |
| `n` | ANR garbage | via adapter | native | native | |
| `P` | dnAttr noise | via adapter | native | native | |
| `L` | Transitive | via adapter | native | native | |

### BaseDN codes

| Code | Name | badldap | impacket | ldap3 | Notes |
|------|------|---------|----------|-------|-------|
| `C` | Case | native | native | native | |
| `S` | Spacing | native | native | **FAIL** | ldap3 DN parser rejects spaces |
| `Q` | Quotes | native | native | **FAIL** | ldap3 DN parser rejects quotes |
| `O` | OID | native | native | **FAIL** | ldap3 DN parser rejects `oID.` |
| `X` | Hex value | native | native | native | |
| `U` | GUID | native | native | native | Alternative DN form, works everywhere |
| `I` | SID | native | native | native | Alternative DN form, works everywhere |

### Tools tested

| Tool | LDAP library | Recommended filter chain | Recommended BaseDN chain |
|------|-------------|------------------------|------------------------|
| **bloodyAD** | badldap | All codes (via ASN1 adapter) | All codes |
| **bloodhound.py** | ldap3 | All except O (or with monkey-patch) | C, X, U, I |
| **impacket** (GetADUsers, GetUserSPNs, etc) | impacket custom | All except O | All codes |
| **NetExec** | impacket | All except O | All codes |
| **Certipy** | ldap3 | All except O (or with monkey-patch) | C, X, U, I |

For step-by-step integration examples with each tool (impacket, NetExec, Certipy, bloodhound.py, bloodyAD), see **[docs/integration-examples.md](docs/integration-examples.md)**.

### Integration notes

**badldap:** Requires ASN1 adapter (`ldapx.adapters.badldap.ast_to_asn1`) + monkey-patch of `query_syntax_converter` to bypass PEG parser. See bloodyAD integration for reference.

**ldap3:** Codes `G` and `O` in filters need monkey-patching `ldap3.protocol.convert.validate_attribute_value` to accept unknown attribute names. **Do not** use `connection.check_names = False` — it breaks response parsing (SIDs, GUIDs, datetimes returned as raw bytes/strings). BaseDN codes `S`, `Q`, `O` fail due to ldap3's strict `safe_dn()` parser — use `U` (GUID) or `I` (SID) instead.

**impacket:** Code `O` (OID) in filters fails due to impacket's filter parser rejecting `oID.` prefix. All other codes work natively. BaseDN accepts all codes including alternative DN forms.

### General AD limitations (all libraries)

- **AttrEntries code O:** AD rejects OID attribute names in modify/add operations
- **AttrList codes W/w/p/e:** Change query semantics (what server returns), may break response parsing
- **NTLM signing/sealing:** Obfuscation works (applied before encryption), but not visible on the wire with Wireshark

## Proxy Mode

This library provides **programmatic obfuscation** (library + CLI). If you need **proxy mode** — intercepting and transforming LDAP packets on the fly between any tool and an LDAP server, without modifying source code — use the Go version:

- [github.com/Macmod/ldapx](https://github.com/Macmod/ldapx) — LDAP proxy with real-time packet transformation, interactive shell, LDAPS/SOCKS support

## Credits

- [Daniel Bohannon (@danielhbohannon)](https://x.com/danielhbohannon) & [Sabajete Elezaj (@sabi_elezi)](https://x.com/sabi_elezi) — Almost all obfuscation techniques implemented here originate from their [MaLDAPtive](https://www.youtube.com/watch?v=mKRS5Iyy7Qo) research. Kudos to them.
- [Artur Marzano (@Macmod)](https://github.com/Macmod) — Author of the original [ldapx](https://github.com/Macmod/ldapx) in Go, which implements the MaLDAPtive research into a practical tool. This project is a Python port of his work.

## License

MIT - see [LICENSE](LICENSE)
