"""
Middleware options - configurable parameters for obfuscation middlewares.

Mirrors Go ldapx middlewares/options.go DefaultOptions.
"""


_DEFAULTS = {
    # Filter options
    "FiltCaseProb": 0.5,
    "FiltSpacingMaxSpaces": 3,
    "FiltGarbageMaxElems": 1,
    "FiltGarbageSize": 10,
    "FiltHexValueProb": 0.3,
    "FiltTimestampMaxChars": 5,
    "FiltTimestampUseComma": False,
    "FiltBoolMaxDepth": 2,
    "FiltBoolProb": 0.5,
    "FiltBitwiseMaxBits": 31,
    "FiltOIDMaxSpaces": 2,
    "FiltOIDMaxZeros": 2,
    "FiltOIDIncludePrefix": False,
    "FiltSubstringSplitProb": 0.3,
    "FiltPrependZerosMax": 3,
    "FiltANRGarbageMaxChars": 10,
    # BaseDN options
    "BDNCaseProb": 0.5,
    "BDNSpacingMaxSpaces": 2,
    "BDNHexValueProb": 0.3,
    "BDNOIDMaxSpaces": 2,
    "BDNOIDMaxZeros": 2,
    "BDNOIDIncludePrefix": False,
    # AttrList options
    "AttrsCaseProb": 0.5,
    "AttrsDuplicateProb": 0.3,
    "AttrsGarbageMaxElems": 2,
    "AttrsGarbageSize": 10,
    "AttrsOIDMaxSpaces": 2,
    "AttrsOIDMaxZeros": 2,
    "AttrsOIDIncludePrefix": False,
    "AttrsExistingGarbageMax": 2,
    # AttrEntries options
    "AttrEntriesCaseProb": 0.5,
}


class Options:
    """Configurable parameters for middleware factories.

    Usage:
        opts = Options(FiltCaseProb=0.8, FiltOIDMaxSpaces=4)
        result = ldapx.obfuscate_filter("(cn=admin)", "CO", options=opts)
    """

    def __init__(self, **overrides):
        self._values = {**_DEFAULTS, **overrides}

    def get(self, key, default=None):
        return self._values.get(key, _DEFAULTS.get(key, default))

    def set(self, key, value):
        self._values[key] = value

    @classmethod
    def defaults(cls):
        """Return a new Options instance with all defaults."""
        return cls()
