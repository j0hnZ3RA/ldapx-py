"""
Adapters for integrating ldapx with specific LDAP libraries.

Each adapter converts ldapx Filter AST objects to the target library's
native filter representation. The core ldapx library is LDAP-library
agnostic - it works with strings and its own AST types.

Available adapters:
  - badldap: Convert to badldap ASN1 Filter objects (pip install ldapx[badldap])
"""
