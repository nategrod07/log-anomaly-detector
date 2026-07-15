"""Replay a log file at a syslog listener, one UDP datagram per line.

Usage:
    python3 scripts/replay_syslog.py [FILE] [--host HOST] [--port PORT] [--delay SECONDS]

FILE defaults to sample_logs/syslog_samples.log.
"""

import argparse
import socket
import time
from pathlib import Path

DEFAULT_FILE = Path(__file__).resolve().parent.parent / "sample_logs" / "syslog_samples.log"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", default=str(DEFAULT_FILE), help="log file to replay, one message per line")
    parser.add_argument("--host", default="127.0.0.1", help="listener host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5514, help="listener UDP port (default: 5514)")
    parser.add_argument("--delay", type=float, default=0.3, help="seconds to wait between messages (default: 0.3)")
    args = parser.parse_args()

    with open(args.file, "rb") as f:
        lines = [line.rstrip(b"\n") for line in f if line.strip()]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for line in lines:
            sock.sendto(line, (args.host, args.port))
            time.sleep(args.delay)
    finally:
        sock.close()

    print(f"sent {len(lines)} messages to {args.host}:{args.port}")


if __name__ == "__main__":
    main()
