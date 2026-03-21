"""
Filter middleware type definitions and chain class.
"""

import logging
from typing import Callable

from ldapx.parser.filter import Filter

LOG = logging.getLogger(__name__)

# Type alias matching Go's FilterMiddleware = func(Filter) Filter
FilterMiddleware = Callable[[Filter], Filter]


class FilterMiddlewareChain:
    """Ordered chain of filter middlewares, matching Go FilterMiddlewareChain."""

    def __init__(self):
        self._middlewares: list = []

    def add(self, name: str, factory: Callable[[], FilterMiddleware]):
        """Add a middleware factory to the chain."""
        self._middlewares.append((name, factory))

    def execute(self, f: Filter, verbose: bool = False) -> Filter:
        """Execute all middlewares in order on the given filter."""
        for name, factory in self._middlewares:
            if verbose:
                LOG.info("Applying filter middleware: %s", name)
            mw = factory()
            f = mw(f)
        return f
