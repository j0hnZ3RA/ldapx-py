"""AttrEntries middleware type definitions and chain class."""

import logging
from typing import Callable, Dict, List

LOG = logging.getLogger(__name__)

AttrEntriesMiddleware = Callable[[Dict[str, List]], Dict[str, List]]


class AttrEntriesMiddlewareChain:
    """Ordered chain of attribute entries middlewares (for modify/add)."""

    def __init__(self):
        self._middlewares: list = []

    def add(self, name: str, factory: Callable[[], AttrEntriesMiddleware]):
        self._middlewares.append((name, factory))

    def execute(self, entries: Dict[str, List], verbose: bool = False) -> Dict[str, List]:
        for name, factory in self._middlewares:
            if verbose:
                LOG.info("Applying AttrEntries middleware: %s", name)
            mw = factory()
            entries = mw(entries)
        return entries
