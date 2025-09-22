# LogSentry

---

## LogSentry — Log Analyzer & Incident Detector**

```markdown
# LogSentry

**LogSentry** — web log analyzer that detects suspicious activity. Perfect for showcasing log analysis and cybersecurity skills.

---

## ⚡ Features

- Parse Apache/Nginx Common and Combined log formats
- Count top IPs, URLs, and HTTP codes
- Detect suspicious IPs based on 404/5xx thresholds
- Export reports to JSON and CSV
- Configurable detection thresholds

---

## 🚀 Usage

```bash
# Analyze a local log file
python3 logsentry.py access.log

# Adjust thresholds and save report
python3 logsentry.py access.log --404-thresh 20 --5xx-thresh 5 --json report.json --csv-paths top_paths.csv

