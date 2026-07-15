"""Log ingestion adapters that normalize wire-format logs into LogEvent."""

from detector.ingestion.base import BaseIngestor
from detector.ingestion.syslog_listener import SyslogUDPIngestor

__all__ = ["BaseIngestor", "SyslogUDPIngestor"]
