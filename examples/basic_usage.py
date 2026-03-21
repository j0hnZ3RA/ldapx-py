"""Basic usage examples for ldapx."""

import ldapx

# --- Filter obfuscation ---

print("=== Filter Obfuscation ===\n")

# Simple case + OID
original = "(sAMAccountName=admin)"
result = ldapx.obfuscate_filter(original, "CO")
print(f"Original: {original}")
print(f"CO:       {result}\n")

# Aggressive chain
result = ldapx.obfuscate_filter(original, "COGDRM")
print(f"COGDRM:   {result}\n")

# --- BaseDN obfuscation ---

print("=== BaseDN Obfuscation ===\n")

original = "DC=corp,DC=local"
result = ldapx.obfuscate_basedn(original, "COQ")
print(f"Original: {original}")
print(f"COQ:      {result}\n")

# --- AttrList obfuscation ---

print("=== AttrList Obfuscation ===\n")

attrs = ["cn", "sAMAccountName", "memberOf"]
result = ldapx.obfuscate_attrlist(attrs, "COR")
print(f"Original: {attrs}")
print(f"COR:      {result}\n")

# --- AttrEntries obfuscation ---

print("=== AttrEntries Obfuscation ===\n")

entries = {"cn": [b"TestUser"], "description": [b"A test user"]}
result = ldapx.obfuscate_attrentries(entries, "CR")
print(f"Original: {entries}")
print(f"CR:       {result}\n")

# --- Custom options ---

print("=== Custom Options ===\n")

opts = ldapx.Options(FiltCaseProb=1.0, FiltOIDMaxSpaces=5)
result = ldapx.obfuscate_filter("(cn=admin)", "CO", options=opts)
print(f"With custom options: {result}")
