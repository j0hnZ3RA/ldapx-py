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

### BaseDN (`-b`)

| Code | Name | Description |
|------|------|-------------|
| `C` | Random case | Randomize case |
| `S` | Random spacing | Add spaces around DN |
| `Q` | Double quotes | Wrap DN values in quotes |
| `O` | OID attributes | Replace DN attr names with OIDs |
| `X` | Hex value encoding | Hex-encode DN value characters |

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

## Go Version

For LDAP proxy mode (intercept and transform packets on the fly), use the Go version: [github.com/Macmod/ldapx](https://github.com/Macmod/ldapx)

## License

MIT - see [LICENSE](LICENSE)
