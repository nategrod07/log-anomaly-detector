"""Tests for the syslog UDP ingestion adapter."""

import queue
import socket
import threading
from datetime import datetime, timezone

import pytest

from detector.ingestion.syslog_listener import (
    SyslogUDPIngestor,
    _decode_priority,
    _parse_rfc3164_timestamp,
    _parse_rfc5424_timestamp,
    _split_structured_data,
)


# --- PRI decoding ------------------------------------------------------


def test_decode_priority_rfc3164_example():
    # <34> from the RFC 3164 section 5.4 example message.
    assert _decode_priority(34) == ("auth", "crit")


def test_decode_priority_rfc5424_example():
    # <165> from the RFC 5424 section 6.5 example message.
    assert _decode_priority(165) == ("local4", "notice")


def test_decode_priority_out_of_range():
    assert _decode_priority(999) == (None, None)


# --- Timestamp parsing ---------------------------------------------------


def test_parse_rfc3164_timestamp_same_year():
    now = datetime(2026, 7, 20, tzinfo=timezone.utc)
    parsed = _parse_rfc3164_timestamp("Jul 15 08:41:02", now=now)
    assert parsed == datetime(2026, 7, 15, 8, 41, 2, tzinfo=timezone.utc)


def test_parse_rfc3164_timestamp_rolls_back_year_at_boundary():
    # A "Dec 31" message received after the clock has rolled into January
    # must be attributed to the previous year, not treated as being from
    # the future.
    now = datetime(2027, 1, 3, tzinfo=timezone.utc)
    parsed = _parse_rfc3164_timestamp("Dec 31 23:59:00", now=now)
    assert parsed == datetime(2026, 12, 31, 23, 59, 0, tzinfo=timezone.utc)


def test_parse_rfc3164_timestamp_rejects_garbage():
    assert _parse_rfc3164_timestamp("not a timestamp") is None


def test_parse_rfc5424_timestamp_with_z_suffix():
    parsed = _parse_rfc5424_timestamp("2003-10-11T22:14:15.003Z")
    assert parsed == datetime(2003, 10, 11, 22, 14, 15, 3000, tzinfo=timezone.utc)


def test_parse_rfc5424_timestamp_nilvalue():
    assert _parse_rfc5424_timestamp("-") is None


def test_parse_rfc5424_timestamp_rejects_garbage():
    assert _parse_rfc5424_timestamp("not-a-timestamp") is None


# --- Structured data splitting --------------------------------------------


def test_split_structured_data_nilvalue():
    assert _split_structured_data("- An application event log entry") == (
        "-",
        "An application event log entry",
    )


def test_split_structured_data_single_element():
    sd, msg = _split_structured_data('[exampleSDID@32473 iut="3"] hello world')
    assert sd == '[exampleSDID@32473 iut="3"]'
    assert msg == "hello world"


def test_split_structured_data_multiple_elements():
    remainder = (
        '[exampleSDID@32473 iut="3" eventSource="Application"]'
        '[examplePriority@32473 class="high"] An application event log entry'
    )
    sd, msg = _split_structured_data(remainder)
    assert sd == (
        '[exampleSDID@32473 iut="3" eventSource="Application"]'
        '[examplePriority@32473 class="high"]'
    )
    assert msg == "An application event log entry"


def test_split_structured_data_bracket_inside_quoted_value():
    # A quoted SD-PARAM value containing "]" must not be mistaken for the
    # end of the SD-ELEMENT.
    sd, msg = _split_structured_data('[id@1 note="[nested]"] the message')
    assert sd == '[id@1 note="[nested]"]'
    assert msg == "the message"


def test_split_structured_data_malformed_falls_back_to_message():
    assert _split_structured_data("not bracketed or a dash") == (
        "-",
        "not bracketed or a dash",
    )


# --- Full message parsing -------------------------------------------------


@pytest.fixture
def ingestor():
    adapter = SyslogUDPIngestor(host="127.0.0.1", port=0)
    yield adapter
    adapter.stop()


def test_parses_rfc3164_message(ingestor):
    raw = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
    event = ingestor._parse(raw, "10.0.0.5")

    assert event.source_format == "syslog"
    assert event.host == "mymachine"
    assert event.facility == "auth"
    assert event.severity == "crit"
    assert event.process == "su"
    assert event.pid is None
    assert event.message == "'su root' failed for lonvick on /dev/pts/8"
    assert event.source_ip == "10.0.0.5"
    assert event.extra["rfc"] == "3164"


def test_parses_rfc3164_message_with_pid(ingestor):
    raw = b"<13>Jul 15 08:41:02 web01 sshd[9421]: Accepted publickey for deploy"
    event = ingestor._parse(raw, "10.0.4.12")

    assert event.process == "sshd"
    assert event.pid == "9421"
    assert event.message == "Accepted publickey for deploy"


def test_parses_rfc5424_message(ingestor):
    raw = (
        b'<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 '
        b'[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] '
        b"An application event log entry"
    )
    event = ingestor._parse(raw, "192.168.1.1")

    assert event.host == "mymachine.example.com"
    assert event.facility == "local4"
    assert event.severity == "notice"
    assert event.process == "evntslog"
    assert event.pid is None
    assert event.message == "An application event log entry"
    assert event.extra["rfc"] == "5424"
    assert event.extra["msgid"] == "ID47"
    assert "exampleSDID@32473" in event.extra["structured_data"]


def test_unparseable_message_falls_back_without_dropping_data(ingestor):
    raw = b"this is not a valid syslog line at all"
    event = ingestor._parse(raw, "203.0.113.9")

    assert event.message == "this is not a valid syslog line at all"
    assert event.raw == event.message
    assert event.host is None
    assert "parse_error" in event.extra


def test_invalid_utf8_does_not_raise(ingestor):
    raw = b"<34>Oct 11 22:14:15 mymachine su: bad byte \xff here"
    event = ingestor._parse(raw, "10.0.0.5")
    assert "bad byte" in event.message


def test_empty_datagram_yields_no_event(ingestor):
    assert ingestor._parse(b"", "10.0.0.5") is None


# --- End-to-end over a real UDP socket -------------------------------------


def test_end_to_end_udp_delivery():
    adapter = SyslogUDPIngestor(host="127.0.0.1", port=0)
    received: "queue.Queue" = queue.Queue()

    def consume():
        for event in adapter.events():
            received.put(event)

    worker = threading.Thread(target=consume, daemon=True)
    worker.start()

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        client.sendto(
            b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick",
            ("127.0.0.1", adapter.port),
        )
        event = received.get(timeout=2)
        assert event.host == "mymachine"
        assert event.source_ip == "127.0.0.1"
    finally:
        client.close()
        adapter.stop()
        worker.join(timeout=2)
        assert not worker.is_alive()
