"""Example: Using explicit middleware chains (Go-style pattern)."""

from ldapx.parser import query_to_filter, filter_to_query
from ldapx.middlewares.filter import (
    FilterMiddlewareChain,
    rand_case_filter_obf,
    oid_attribute_filter_obf,
    rand_garbage_filter_obf,
    de_morgan_bool_filter_obf,
    rand_bool_reorder_filter_obf,
)

# Build a custom chain
chain = FilterMiddlewareChain()
chain.add("Case", lambda: rand_case_filter_obf(0.7))
chain.add("OID", lambda: oid_attribute_filter_obf(3, 3))
chain.add("Garbage", lambda: rand_garbage_filter_obf(1, 8))
chain.add("DeMorgan", lambda: de_morgan_bool_filter_obf())
chain.add("Reorder", lambda: rand_bool_reorder_filter_obf())

# Parse, execute chain, convert back
query = "(&(objectClass=user)(sAMAccountName=admin))"
print(f"Original: {query}\n")

f = query_to_filter(query)
result = chain.execute(f, verbose=True)
output = filter_to_query(result)
print(f"\nObfuscated: {output}")

# --- Direct composition (flashingestor-style) ---
print("\n--- Direct Composition ---\n")

f = query_to_filter("(cn=admin)")
f = rand_case_filter_obf(0.5)(f)
f = oid_attribute_filter_obf(2, 2)(f)
print(f"Direct: {filter_to_query(f)}")
