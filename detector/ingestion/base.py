"""Abstract interface that every log ingestion adapter implements."""

from abc import ABC, abstractmethod
from typing import Iterator

from detector.schema import LogEvent


class BaseIngestor(ABC):
    """Common contract for all streaming log ingestion adapters.

    Concrete adapters (syslog, file-tailing, Windows Event subscription, ...)
    each speak a different wire protocol but must normalize what they read
    into LogEvent, so every downstream stage can stay format-agnostic.
    """

    @abstractmethod
    def events(self) -> Iterator[LogEvent]:
        """Yield normalized LogEvents as they arrive.

        This blocks between events, so callers that need to do other work
        concurrently should drive it from its own thread.
        """
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        """Signal the ingestor to stop yielding new events.

        Must be safe to call from a different thread than the one
        iterating events() — implementations should not assume otherwise.
        """
        raise NotImplementedError
