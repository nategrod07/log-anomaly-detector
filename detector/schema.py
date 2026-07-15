"""Common normalized event representation shared by every ingestion adapter.

Every ingestion adapter (syslog, Windows Event Log, web server logs, ...)
speaks a different wire format but must normalize what it reads into a
LogEvent, so downstream stages (feature extraction, detection, alerting)
never need to know where an event came from.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class LogEvent:
    """A single normalized log event.

    Fields that a given source format doesn't provide are left as None
    rather than guessed. Format-specific data that doesn't map cleanly onto
    this schema (e.g. syslog structured-data, a Windows Event's XML fields)
    belongs in `extra` instead of widening this schema per source format.
    """

    timestamp: datetime
    source_format: str
    message: str
    raw: str
    host: Optional[str] = None
    severity: Optional[str] = None
    facility: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[str] = None
    source_ip: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
