"""UDP syslog ingestion adapter.

Accepts both legacy BSD syslog (RFC 3164) and modern syslog (RFC 5424)
messages on a single UDP socket, normalizing either into a LogEvent.

Security note: everything this module reads is untrusted, potentially
adversarial network input. Parsing is intentionally strict-but-non-fatal —
a message that doesn't match either RFC format is never dropped or allowed
to crash the listener; it's preserved as a fallback LogEvent so a malformed
or hostile payload can't be used to silently evade detection.
"""

import re
import socket
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, Match, Optional, Tuple

from detector.ingestion.base import BaseIngestor
from detector.schema import LogEvent

# RFC 5424 section 6.2.1, table 1: facility = pri // 8.
_FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "security", "console",
    "solaris-cron", "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7",
]
# RFC 5424 section 6.2.1, table 2: severity = pri % 8.
_SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

_RFC3164_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Fixed-structure patterns only (no nested/overlapping quantifiers), so
# these can't be driven into catastrophic backtracking by adversarial input.
_RFC5424_HEADER_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) "
    r"(?P<timestamp>\S+) (?P<hostname>\S+) (?P<appname>\S+) "
    r"(?P<procid>\S+) (?P<msgid>\S+) (?P<remainder>.*)$"
)
_RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>\S+) "
    r"(?P<tag>[^:\[]+)(?:\[(?P<pid>\d+)\])?: ?"
    r"(?P<message>.*)$"
)
_RFC3164_TIMESTAMP_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})$")


def _decode_priority(pri: int) -> Tuple[Optional[str], Optional[str]]:
    """Split a syslog PRI value into (facility, severity) names."""
    if not 0 <= pri <= 191:
        return None, None
    facility_num, severity_num = divmod(pri, 8)
    facility = _FACILITIES[facility_num] if facility_num < len(_FACILITIES) else None
    return facility, _SEVERITIES[severity_num]


def _none_if_nil(value: str) -> Optional[str]:
    """RFC 5424 uses "-" as an explicit "field not present" nilvalue."""
    return None if value == "-" else value


def _parse_rfc5424_timestamp(value: str) -> Optional[datetime]:
    if value == "-":
        return None
    # datetime.fromisoformat only accepts "Z" as a UTC suffix from Python
    # 3.11 onward; normalize it ourselves so this works on 3.9/3.10 too.
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _parse_rfc3164_timestamp(value: str, *, now: Optional[datetime] = None) -> Optional[datetime]:
    """Parse an RFC 3164 "Mmm dd hh:mm:ss" timestamp (no year on the wire).

    Uses a fixed English month-name table rather than strptime's "%b",
    since "%b" depends on the process locale and RFC 3164 month names are
    always English regardless of system configuration.

    The wire format has no year, so the current year is assumed. If that
    would place the timestamp more than a day in the future (e.g. a
    "Dec 31" message arriving after the local clock has rolled to
    January), the previous year is assumed instead.
    """
    now = now or datetime.now(timezone.utc)
    match = _RFC3164_TIMESTAMP_RE.match(value)
    if not match:
        return None
    month_name, day, hour, minute, second = match.groups()
    month = _RFC3164_MONTHS.get(month_name)
    if month is None:
        return None
    try:
        candidate = datetime(now.year, month, int(day), int(hour), int(minute), int(second), tzinfo=timezone.utc)
    except ValueError:
        return None
    if candidate - now > timedelta(days=1):
        candidate = candidate.replace(year=now.year - 1)
    return candidate


def _split_structured_data(remainder: str) -> Tuple[str, str]:
    """Split RFC 5424 "SD MSG" into (structured_data, message).

    Structured data is either the nilvalue "-" or one or more bracketed
    SD-ELEMENTs with no space between them (RFC 5424 section 6.3). Balanced
    bracket matching isn't a regular language, so this is scanned by hand
    (tracking bracket depth and quoted-string state) instead of forcing it
    through a single regex.
    """
    if remainder == "-":
        return "-", ""
    if remainder.startswith("- "):
        return "-", remainder[2:]
    if not remainder.startswith("["):
        return "-", remainder  # Malformed SD field; treat it all as MSG.

    depth = 0
    in_quotes = False
    escaped = False
    sd_end = None
    for i, ch in enumerate(remainder):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quotes:
            escaped = True
        elif ch == '"':
            in_quotes = not in_quotes
        elif ch == "[" and not in_quotes:
            depth += 1
        elif ch == "]" and not in_quotes:
            depth -= 1
            if depth == 0:
                sd_end = i + 1
                # STRUCTURED-DATA is 1*SD-ELEMENT with no separator between
                # them, so another element may start immediately.
                if sd_end < len(remainder) and remainder[sd_end] == "[":
                    continue
                break

    if sd_end is None:
        return "-", remainder  # Unbalanced brackets; treat it all as MSG.

    structured_data = remainder[:sd_end]
    rest = remainder[sd_end:]
    message = rest[1:] if rest.startswith(" ") else rest
    return structured_data, message


class SyslogUDPIngestor(BaseIngestor):
    """Listens for syslog messages on a UDP socket and yields LogEvents.

    IPv4 only for now; IPv6 support (AF_INET6) can be added as a second
    adapter or a constructor option if a source that needs it comes up.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 5514, buffer_size: int = 8192) -> None:
        """Bind the listening socket immediately.

        Binding here (rather than lazily in events()) means construction
        fails fast if the port is unavailable, and self.port is valid as
        soon as the object exists — useful for tests that bind port 0 and
        need to read back the OS-assigned port before sending anything.

        buffer_size defaults to 8192 bytes: RFC 5426 asks receivers to
        support at least 2048 octets per datagram, and 8192 comfortably
        covers real-world senders while still bounding worst-case memory
        use per received message.
        """
        self.buffer_size = buffer_size
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((host, port))
        self._socket.settimeout(1.0)
        self._running = False

    @property
    def port(self) -> int:
        """The bound port (resolves port=0 to the OS-assigned ephemeral port)."""
        return self._socket.getsockname()[1]

    def events(self) -> Iterator[LogEvent]:
        """Receive datagrams and yield a LogEvent per message until stop() is called.

        Uses a 1-second recv timeout to poll the stop flag rather than
        blocking forever, so stop() (called from another thread) is
        noticed within about a second instead of not at all.
        """
        self._running = True
        try:
            while self._running:
                try:
                    data, (source_ip, _source_port) = self._socket.recvfrom(self.buffer_size)
                except socket.timeout:
                    continue
                event = self._parse(data, source_ip)
                if event is not None:
                    yield event
        finally:
            self._socket.close()

    def stop(self) -> None:
        # Closing here (in addition to the events() finally block) makes
        # stop() release the socket even if events() was never iterated,
        # and socket.close() is safe to call more than once.
        self._running = False
        self._socket.close()

    def _parse(self, data: bytes, source_ip: str) -> Optional[LogEvent]:
        # Never raise on bad encoding: replace invalid bytes rather than
        # dropping a message an attacker could craft to evade parsing.
        raw_text = data.decode("utf-8", errors="replace").lstrip("\ufeff").rstrip("\r\n")
        if not raw_text:
            return None

        match = _RFC5424_HEADER_RE.match(raw_text)
        if match:
            return self._build_rfc5424_event(match, raw_text, source_ip)

        match = _RFC3164_RE.match(raw_text)
        if match:
            return self._build_rfc3164_event(match, raw_text, source_ip)

        return self._build_fallback_event(raw_text, source_ip)

    def _build_rfc5424_event(self, match: "Match[str]", raw_text: str, source_ip: str) -> LogEvent:
        fields = match.groupdict()
        facility, severity = _decode_priority(int(fields["pri"]))
        structured_data, message = _split_structured_data(fields["remainder"])
        timestamp = _parse_rfc5424_timestamp(fields["timestamp"]) or datetime.now(timezone.utc)
        extra: Dict[str, Any] = {
            "rfc": "5424",
            "msgid": _none_if_nil(fields["msgid"]),
            "structured_data": structured_data,
        }
        return LogEvent(
            timestamp=timestamp,
            source_format="syslog",
            host=_none_if_nil(fields["hostname"]),
            severity=severity,
            facility=facility,
            process=_none_if_nil(fields["appname"]),
            pid=_none_if_nil(fields["procid"]),
            message=message,
            raw=raw_text,
            source_ip=source_ip,
            extra=extra,
        )

    def _build_rfc3164_event(self, match: "Match[str]", raw_text: str, source_ip: str) -> LogEvent:
        fields = match.groupdict()
        facility, severity = _decode_priority(int(fields["pri"]))
        timestamp = _parse_rfc3164_timestamp(fields["timestamp"]) or datetime.now(timezone.utc)
        return LogEvent(
            timestamp=timestamp,
            source_format="syslog",
            host=fields["hostname"],
            severity=severity,
            facility=facility,
            process=fields["tag"].strip(),
            pid=fields.get("pid"),
            message=fields["message"],
            raw=raw_text,
            source_ip=source_ip,
            extra={"rfc": "3164"},
        )

    def _build_fallback_event(self, raw_text: str, source_ip: str) -> LogEvent:
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_format="syslog",
            host=None,
            severity=None,
            facility=None,
            process=None,
            pid=None,
            message=raw_text,
            raw=raw_text,
            source_ip=source_ip,
            extra={"parse_error": "did not match RFC 3164 or RFC 5424 syslog header"},
        )
