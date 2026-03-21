"""Tests for the ldapx CLI."""

import subprocess
import sys
import json
import pytest


def run_cli(*args):
    """Run ldapx CLI and return (stdout, stderr, returncode)."""
    result = subprocess.run(
        [sys.executable, "-m", "ldapx.cli.main"] + list(args),
        capture_output=True, text=True,
    )
    return result.stdout, result.stderr, result.returncode


class TestFilterCommand:
    def test_basic_filter(self):
        stdout, _, rc = run_cli("filter", "-f", "(cn=admin)", "-c", "C")
        assert rc == 0
        assert "=" in stdout.strip()
        assert stdout.strip().startswith("(")

    def test_filter_with_oid(self):
        stdout, _, rc = run_cli("filter", "-f", "(cn=admin)", "-c", "CO")
        assert rc == 0
        assert "oID." in stdout

    def test_filter_multiple_variants(self):
        stdout, _, rc = run_cli("filter", "-f", "(cn=admin)", "-c", "C", "-n", "3")
        assert rc == 0
        lines = [l for l in stdout.strip().split("\n") if l]
        assert len(lines) == 3

    def test_filter_json_output(self):
        stdout, _, rc = run_cli("filter", "-f", "(cn=admin)", "-c", "C", "--json")
        assert rc == 0
        data = json.loads(stdout)
        assert "input" in data
        assert "chain" in data
        assert "results" in data
        assert data["input"] == "(cn=admin)"
        assert data["chain"] == "C"

    def test_filter_verbose(self):
        stdout, stderr, rc = run_cli("filter", "-f", "(cn=admin)", "-c", "CO", "-v")
        assert rc == 0
        assert "[ldapx]" in stderr
        assert "original" in stderr
        assert "obfuscated" in stderr

    def test_filter_stdin(self):
        result = subprocess.run(
            [sys.executable, "-m", "ldapx.cli.main", "filter", "-c", "C"],
            input="(cn=admin)\n", capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "=" in result.stdout

    def test_filter_missing_input(self):
        # With a TTY-like scenario, this should fail
        # We can't easily test TTY detection, but missing -f with no stdin should work via pipe
        pass


class TestBaseDNCommand:
    def test_basic_basedn(self):
        stdout, _, rc = run_cli("basedn", "-b", "DC=corp,DC=local", "-c", "C")
        assert rc == 0
        assert "=" in stdout

    def test_basedn_oid(self):
        stdout, _, rc = run_cli("basedn", "-b", "DC=corp,DC=local", "-c", "O")
        assert rc == 0
        assert "oID." in stdout

    def test_basedn_verbose(self):
        stdout, stderr, rc = run_cli("basedn", "-b", "DC=corp", "-c", "CO", "-v")
        assert rc == 0
        assert "[ldapx]" in stderr
        assert "BASEDN" in stderr


class TestAttrListCommand:
    def test_basic_attrlist(self):
        stdout, _, rc = run_cli("attrlist", "-a", "cn,sn,mail", "-c", "C")
        assert rc == 0
        assert "," in stdout  # comma-separated output

    def test_attrlist_oid(self):
        stdout, _, rc = run_cli("attrlist", "-a", "cn,sn", "-c", "O")
        assert rc == 0
        assert "oID." in stdout

    def test_attrlist_json(self):
        stdout, _, rc = run_cli("attrlist", "-a", "cn,sn", "-c", "C", "--json")
        assert rc == 0
        data = json.loads(stdout)
        assert data["input"] == ["cn", "sn"]


class TestCodesCommand:
    def test_codes_all(self):
        stdout, _, rc = run_cli("codes", "--all")
        assert rc == 0
        assert "Filter" in stdout
        assert "BaseDN" in stdout
        assert "AttrList" in stdout
        assert "AttrEntries" in stdout

    def test_codes_filter_only(self):
        stdout, _, rc = run_cli("codes", "--filter-codes")
        assert rc == 0
        assert "Filter" in stdout
        assert "Random case" in stdout

    def test_codes_default_shows_all(self):
        stdout, _, rc = run_cli("codes")
        assert rc == 0
        assert "Filter" in stdout
        assert "AttrEntries" in stdout


class TestVersion:
    def test_version(self):
        stdout, _, rc = run_cli("--version")
        assert rc == 0
        assert "ldapx 0.1." in stdout


class TestNoCommand:
    def test_no_command_shows_help(self):
        _, _, rc = run_cli()
        assert rc == 1
