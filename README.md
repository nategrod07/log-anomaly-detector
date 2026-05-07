# Log Anomaly Detector

A Python CLI tool that ingests system logs and flags anomalous behavior using statistical methods and machine learning. Built to detect brute force attacks, port scans, credential stuffing, and unusual access patterns in syslog and auth log files.

---

## How it works

Raw log lines pass through a five-stage pipeline:

```
Log files / stdin
      ↓
  Ingestor       — reads plain files, rotated logs (.1, .2.gz), or stdin
      ↓
   Parser        — extracts timestamp, hostname, service, IP, username
      ↓
Feature engineering — rolling 5-min windows: fail ratio, unique IPs, event rate
      ↓
  Detection      — Z-score / IQR (statistical) + Isolation Forest (ML)
      ↓
  Reporter       — terminal summary + JSON report
```

The key insight is that anomalies in logs rarely appear in a single line — they show up as patterns over time. The feature engineering layer converts raw events into time-windowed metrics, which both detection methods then analyze.

---

## Detection methods

**Statistical (Z-score / IQR)**
Fast, interpretable, and requires no training data. Flags windows where a metric (e.g. `fail_ratio`, `events_per_min`) deviates significantly from the rolling baseline. A `fail_ratio` Z-score above 3.0 is almost always a brute force attempt.

**Isolation Forest**
An unsupervised ML model that learns what "normal" looks like across all features simultaneously. Catches multi-dimensional anomalies that no single metric would flag — for example, a moderate fail rate combined with an unusual hour and a new source IP.

Both signals are combined and deduplicated by the scorer, which assigns a severity tier (INFO / WARN / CRITICAL) to each flagged window.

---

## Installation

```bash
git clone https://github.com/nategrod07/log-anomaly-detector.git
cd log-anomaly-detector

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

---

## Usage

**Analyze a log file:**
```bash
python cli.py --source /var/log/syslog
```

**Analyze rotated logs (reads syslog, syslog.1, syslog.2.gz automatically):**
```bash
python cli.py --source /var/log/syslog --rotated
```

**Pipe from stdin:**
```bash
cat /var/log/auth.log | python cli.py
```

**Write JSON report:**
```bash
python cli.py --source /var/log/syslog --output report.json
```

**Run on the included sample log:**
```bash
python cli.py --source sample_logs/syslog.sample
```

---

## Sample output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Log Anomaly Detector — Analysis Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Source      : syslog.sample
  Lines read  : 78
  Windows     : 24  (5-min buckets)
  Anomalies   : 3

[CRITICAL] 2024-05-02 14:00 — 20 failed auths in 20s
  fail_ratio  : 0.95  (z=6.2)
  unique_ips  : 1  (91.195.240.117)
  method      : statistical + isolation_forest

[WARN]     2024-05-02 04:02 — port scan detected
  unique_ports: 8  blocked by UFW
  source_ip   : 198.51.100.99
  method      : statistical

[WARN]     2024-05-01 14:33 — credential stuffing pattern
  unique_users: 6  tried in 30s
  source_ip   : 45.33.32.156
  method      : isolation_forest
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Project structure

```
log-anomaly-detector/
├── cli.py                  # argparse entry point
├── requirements.txt
├── detector/
│   ├── ingestor.py         # file/stdin reading, gzip, log rotation
│   ├── parser.py           # regex parsing, schema normalization
│   ├── features.py         # rolling window feature extraction
│   ├── statistical.py      # Z-score and IQR detection
│   ├── isolation.py        # Isolation Forest model
│   ├── scorer.py           # signal merging, severity tiers
│   └── reporter.py         # terminal + JSON output
├── sample_logs/
│   └── syslog.sample       # realistic sample with embedded anomalies
└── tests/
    ├── test_parser.py
    └── test_features.py
```

---

## Requirements

```
pandas
scikit-learn
rich
pytest
```

Python 3.10+

---

## What it detects

| Pattern | Method | Signal |
|---|---|---|
| SSH brute force | Statistical | `fail_ratio` spike |
| Credential stuffing | Both | `unique_users` burst |
| Distributed scan | Isolation Forest | `unique_ips` + low `fail_ratio` |
| Port scanning | Statistical | UFW block rate |
| Off-hours access | Isolation Forest | `hour_of_day` anomaly |
| Sudden traffic spike | Statistical | `events_per_min` Z-score |

---

## Contributing

Issues and pull requests welcome. If you have real-world log samples that expose detection gaps, please open an issue.

---

## License

MIT
