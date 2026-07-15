# Log Anomaly Detector

A modular, Python log anomaly detector: ingests logs from multiple sources, normalizes them into a common schema, and flags anomalous activity with statistical and machine-learning scoring.

## Status

Early stage. Built so far:

- A common `LogEvent` schema and a pluggable `BaseIngestor` interface that every ingestion adapter implements.
- A syslog UDP ingestion adapter supporting both RFC 3164 (legacy BSD) and RFC 5424 (modern) syslog.

Not yet built: additional ingestion adapters (JSON/web logs, Windows Event Logs), feature extraction, the detection engine, and alerting.

## Architecture

Planned pipeline — each stage is its own module behind a common interface:

```
Log sources -> Ingestion & parsing -> Feature extraction -> Detection engine -> Alerting & reporting
                                                                   |
                                                             Baselines store
```

- **Ingestion & parsing** — format-specific adapters (syslog, JSON/web logs, Windows Event Logs) normalize everything into one `LogEvent` schema.
- **Feature extraction** — turns events into detection signals (rate windows, rare-value flags, sequences).
- **Detection engine** — pluggable scorers; a statistical scorer and an ML scorer (e.g. Isolation Forest) sit behind one interface.
- **Alerting & reporting** — turns scores into ranked, thresholded findings.
- **Baselines store** — persists historical stats and model state that the detection engine reads and writes.

Target scope covers syslog, JSON/app logs, Windows Event Logs, and Apache/Nginx web logs, ingested and scored in real time rather than in batch.

## Requirements

- Python 3.9+
- Dependencies in `requirements.txt` (numpy, pandas, scikit-learn, pytest)

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Steps to use

**1. Run the tests**

```bash
source venv/bin/activate
pytest
```

**2. Start the syslog listener** (in one terminal)

```bash
source venv/bin/activate
python3 scripts/run_listener.py
```

Listens on UDP `127.0.0.1:5514` by default and prints each normalized event as it arrives. Change the address with `--host` / `--port`. Stop with Ctrl+C.

**3. Send it some logs** (in a second terminal)

```bash
source venv/bin/activate
python3 scripts/replay_syslog.py
```

Replays `sample_logs/syslog_samples.log` at the listener, one UDP datagram per line, with a short pause between messages so you can watch them arrive in the first terminal. Point it at a different file or a different host/port:

```bash
python3 scripts/replay_syslog.py path/to/other.log --host 127.0.0.1 --port 5514 --delay 0.1
```

## Project structure

```
detector/
  schema.py                  # LogEvent - the common normalized event
  ingestion/
    base.py                  # BaseIngestor interface every adapter implements
    syslog_listener.py       # SyslogUDPIngestor (RFC 3164 + RFC 5424)
scripts/
  run_listener.py            # start a listener and print events as they arrive
  replay_syslog.py           # replay a log file at a listener over UDP
sample_logs/
  syslog_samples.log         # mock syslog data for manual testing
test/
  test_syslog_listener.py
```
