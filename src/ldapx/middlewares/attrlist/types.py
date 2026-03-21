"""AttrList middleware type definitions and chain class."""

import logging
from typing import Callable, List

LOG = logging.getLogger(__name__)

AttrListMiddleware = Callable[[List[str]], List[str]]


class AttrListMiddlewareChain:
    """Ordered chain of attribute list middlewares."""

    def __init__(self):
        self._middlewares: list = []

    def add(self, name: str, factory: Callable[[], AttrListMiddleware]):
        self._middlewares.append((name, factory))

    def execute(self, attrs: List[str], verbose: bool = False) -> List[str]:
        for name, factory in self._middlewares:
            if verbose:
                LOG.info("Applying AttrList middleware: %s", name)
            mw = factory()
            attrs = mw(attrs)
        return attrs
