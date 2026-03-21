"""BaseDN middleware type definitions and chain class."""

import logging
from typing import Callable

LOG = logging.getLogger(__name__)

BaseDNMiddleware = Callable[[str], str]


class BaseDNMiddlewareChain:
    """Ordered chain of BaseDN middlewares."""

    def __init__(self):
        self._middlewares: list = []

    def add(self, name: str, factory: Callable[[], BaseDNMiddleware]):
        self._middlewares.append((name, factory))

    def execute(self, basedn: str, verbose: bool = False) -> str:
        for name, factory in self._middlewares:
            if verbose:
                LOG.info("Applying BaseDN middleware: %s", name)
            mw = factory()
            basedn = mw(basedn)
        return basedn
