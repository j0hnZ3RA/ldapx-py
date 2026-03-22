"""
ldapx CLI - LDAP query obfuscation tool.

Usage:
    ldapx filter -f "(cn=admin)" -c "COGDR"
    ldapx basedn -b "DC=corp,DC=local" -c "CSQOX"
    ldapx attrlist -a "cn,sAMAccountName" -c "CRDG"
    ldapx codes --all
"""

import argparse
import json
import logging
import sys

import ldapx


FILTER_CODES = {
    "C": "Random case",
    "S": "Random spacing",
    "G": "Garbage filters",
    "T": "Replace tautologies",
    "R": "Boolean reorder",
    "O": "OID attributes",
    "X": "Hex value encoding",
    "t": "Timestamp garbage",
    "B": "Add random boolean",
    "D": "Double negation",
    "M": "DeMorgan transform",
    "b": "Bitwise breakout",
    "d": "Bitwise decompose",
    "I": "Equality by inclusion",
    "E": "Equality by exclusion",
    "A": "Approx match",
    "x": "Extensible match",
    "Z": "Prepend zeros",
    "s": "Substring split",
    "N": "Names to ANR",
    "n": "ANR garbage substring",
    "P": "dnAttributes noise",
    "L": "Transitive eval (link attrs)",
    "F": "objectCategory form (toggle shortname/DN)",
}

BASEDN_CODES = {
    "C": "Random case",
    "S": "Random spacing",
    "Q": "Double quotes",
    "O": "OID attributes",
    "X": "Hex value encoding",
    "U": "GUID format (requires -o BaseDNGuid=hex)",
    "I": "SID format (requires -o BaseDNSid=S-1-...)",
    "W": "WKGUID format (well-known containers, auto)",
}

ATTRLIST_CODES = {
    "C": "Random case",
    "R": "Reorder list",
    "D": "Duplicate",
    "O": "OID attributes",
    "G": "Garbage (non-existing)",
    "g": "Garbage (existing)",
    "W": "Replace with wildcard",
    "w": "Add wildcard",
    "p": "Add plus (operational)",
    "e": "Replace with empty",
}

ATTRENTRIES_CODES = {
    "C": "Random case",
    "R": "Reorder list",
    "O": "OID attributes",
}


def _parse_options(option_strings):
    """Parse -o KEY=VALUE strings into an Options dict."""
    if not option_strings:
        return None
    overrides = {}
    for s in option_strings:
        if "=" not in s:
            print(f"Warning: ignoring invalid option '{s}' (expected KEY=VALUE)", file=sys.stderr)
            continue
        key, value = s.split("=", 1)
        # Try to parse as number or bool
        if value.lower() in ("true", "false"):
            overrides[key] = value.lower() == "true"
        else:
            try:
                overrides[key] = int(value)
            except ValueError:
                try:
                    overrides[key] = float(value)
                except ValueError:
                    overrides[key] = value
    return ldapx.Options(**overrides) if overrides else None


def cmd_filter(args):
    """Handle 'filter' subcommand."""
    filter_str = args.filter
    if not filter_str:
        if not sys.stdin.isatty():
            filter_str = sys.stdin.read().strip()
        else:
            print("Error: -f/--filter is required (or pipe via stdin)", file=sys.stderr)
            sys.exit(1)

    opts = _parse_options(args.option)
    count = args.count or 1

    results = []
    for _ in range(count):
        result = ldapx.obfuscate_filter(filter_str, args.chain, options=opts, verbose=args.verbose)
        results.append(result)

    if args.json:
        print(json.dumps({"input": filter_str, "chain": args.chain, "results": results}, indent=2))
    else:
        for r in results:
            print(r)


def cmd_basedn(args):
    """Handle 'basedn' subcommand."""
    basedn = args.basedn
    if not basedn:
        if not sys.stdin.isatty():
            basedn = sys.stdin.read().strip()
        else:
            print("Error: -b/--basedn is required (or pipe via stdin)", file=sys.stderr)
            sys.exit(1)

    opts = _parse_options(args.option)
    count = args.count or 1

    results = []
    for _ in range(count):
        result = ldapx.obfuscate_basedn(basedn, args.chain, options=opts, verbose=args.verbose)
        results.append(result)

    if args.json:
        print(json.dumps({"input": basedn, "chain": args.chain, "results": results}, indent=2))
    else:
        for r in results:
            print(r)


def cmd_attrlist(args):
    """Handle 'attrlist' subcommand."""
    attrs_str = args.attrs
    if not attrs_str:
        if not sys.stdin.isatty():
            attrs_str = sys.stdin.read().strip()
        else:
            print("Error: -a/--attrs is required (or pipe via stdin)", file=sys.stderr)
            sys.exit(1)

    attrs = [a.strip() for a in attrs_str.split(",")]
    opts = _parse_options(args.option)
    count = args.count or 1

    results = []
    for _ in range(count):
        result = ldapx.obfuscate_attrlist(attrs, args.chain, options=opts, verbose=args.verbose)
        results.append(result)

    if args.json:
        print(json.dumps({"input": attrs, "chain": args.chain, "results": results}, indent=2))
    else:
        for r in results:
            print(", ".join(r))


def cmd_codes(args):
    """Handle 'codes' subcommand."""
    show_all = args.all or not (args.filter_codes or args.basedn_codes or args.attrlist_codes or args.attrentries_codes)

    sections = []
    if show_all or args.filter_codes:
        sections.append(("Filter", FILTER_CODES))
    if show_all or args.basedn_codes:
        sections.append(("BaseDN", BASEDN_CODES))
    if show_all or args.attrlist_codes:
        sections.append(("AttrList", ATTRLIST_CODES))
    if show_all or args.attrentries_codes:
        sections.append(("AttrEntries", ATTRENTRIES_CODES))

    for name, codes in sections:
        print(f"\n{name} middleware codes:")
        for code, desc in codes.items():
            print(f"  {code} - {desc}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="ldapx",
        description="LDAP query obfuscation tool - Python port of github.com/Macmod/ldapx",
    )
    parser.add_argument("--version", action="version", version=f"ldapx {ldapx.__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # filter
    p_filter = subparsers.add_parser("filter", help="Obfuscate an LDAP filter string")
    p_filter.add_argument("-f", "--filter", help="LDAP filter string (or pipe via stdin)")
    p_filter.add_argument("-c", "--chain", required=True, help="Middleware chain string (e.g., 'COGDR')")
    p_filter.add_argument("-n", "--count", type=int, help="Generate N variants")
    p_filter.add_argument("-o", "--option", action="append", help="Set option KEY=VALUE")
    p_filter.add_argument("--json", action="store_true", help="Output as JSON")
    p_filter.add_argument("-v", "--verbose", action="store_true", help="Show original vs obfuscated")
    p_filter.set_defaults(func=cmd_filter)

    # basedn
    p_basedn = subparsers.add_parser("basedn", help="Obfuscate a BaseDN string")
    p_basedn.add_argument("-b", "--basedn", help="BaseDN string (or pipe via stdin)")
    p_basedn.add_argument("-c", "--chain", required=True, help="Middleware chain string")
    p_basedn.add_argument("-n", "--count", type=int, help="Generate N variants")
    p_basedn.add_argument("-o", "--option", action="append", help="Set option KEY=VALUE")
    p_basedn.add_argument("--json", action="store_true", help="Output as JSON")
    p_basedn.add_argument("-v", "--verbose", action="store_true", help="Show original vs obfuscated")
    p_basedn.set_defaults(func=cmd_basedn)

    # attrlist
    p_attrlist = subparsers.add_parser("attrlist", help="Obfuscate an attribute list")
    p_attrlist.add_argument("-a", "--attrs", help="Comma-separated attribute list (or pipe via stdin)")
    p_attrlist.add_argument("-c", "--chain", required=True, help="Middleware chain string")
    p_attrlist.add_argument("-n", "--count", type=int, help="Generate N variants")
    p_attrlist.add_argument("-o", "--option", action="append", help="Set option KEY=VALUE")
    p_attrlist.add_argument("--json", action="store_true", help="Output as JSON")
    p_attrlist.add_argument("-v", "--verbose", action="store_true", help="Show original vs obfuscated")
    p_attrlist.set_defaults(func=cmd_attrlist)

    # codes
    p_codes = subparsers.add_parser("codes", help="List available middleware codes")
    p_codes.add_argument("--all", action="store_true", help="Show all codes")
    p_codes.add_argument("--filter-codes", action="store_true", help="Show filter codes")
    p_codes.add_argument("--basedn-codes", action="store_true", help="Show BaseDN codes")
    p_codes.add_argument("--attrlist-codes", action="store_true", help="Show AttrList codes")
    p_codes.add_argument("--attrentries-codes", action="store_true", help="Show AttrEntries codes")
    p_codes.set_defaults(func=cmd_codes)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Enable logging for verbose output
    if getattr(args, "verbose", False):
        logging.basicConfig(
            level=logging.WARNING,
            format="%(message)s",
            stream=sys.stderr,
        )

    args.func(args)


if __name__ == "__main__":
    main()
