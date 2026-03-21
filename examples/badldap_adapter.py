"""
Example: Using ldapx with badldap via the adapter.

Requires: pip install ldapx[badldap]
"""

from ldapx.parser import query_to_filter
from ldapx.middlewares.filter import rand_case_filter_obf, oid_attribute_filter_obf

# Parse and obfuscate
f = query_to_filter("(sAMAccountName=admin)")
f = rand_case_filter_obf(0.5)(f)
f = oid_attribute_filter_obf(2, 2)(f)

# Convert to badldap ASN1 (requires badldap installed)
try:
    from ldapx.adapters.badldap import ast_to_asn1

    asn1_filter = ast_to_asn1(f)
    print(f"ASN1 Filter: {asn1_filter}")
    print("Successfully converted to badldap ASN1 Filter object!")
except ImportError:
    print("badldap not installed. Install with: pip install ldapx[badldap]")
    print("Falling back to string output:")

    from ldapx.parser import filter_to_query
    print(f"String: {filter_to_query(f)}")
