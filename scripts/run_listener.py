"""Run the syslog UDP listener and print each normalized event as it arrives.

Usage:
    python3 scripts/run_listener.py [--host HOST] [--port PORT]
"""

import argparse
import sys
from pathlib import Path

# Allows running this script directly (`python3 scripts/run_listener.py`)
# without installing the package, by putting the repo root on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detector.ingestion.syslog_listener import SyslogUDPIngestor  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="interface to listen on (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5514, help="UDP port to listen on, 0 for an OS-assigned port (default: 5514)")
    args = parser.parse_args()

    adapter = SyslogUDPIngestor(host=args.host, port=args.port)
    print(f"listening for syslog on {args.host}:{adapter.port} (Ctrl+C to stop)")
    try:
        for event in adapter.events():
            print(event)
    except KeyboardInterrupt:
        pass
    finally:
        adapter.stop()


if __name__ == "__main__":
    main()
