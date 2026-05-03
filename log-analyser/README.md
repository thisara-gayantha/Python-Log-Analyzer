# Python Log Analyzer

Small Flask application to upload and analyze log files, display statistics
with Chart.js, stream live log lines via Flask-SocketIO, and generate PDF
reports with ReportLab.

The app now includes a security-focused layer that detects suspicious IPs,
repeated authentication failures, and brute-force patterns, then surfaces the
results in the dashboard and PDF report.

## Requirements
- Python 3.10+
- Install dependencies in `requirements.txt` (recommended virtualenv).

## Quick setup

Windows PowerShell example:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run (development)

Run the app (uses Flask-SocketIO). If `eventlet` is installed, Socket.IO
will use it automatically for async support.

```powershell
python app.py
```

Open http://localhost:5000

## Production hint

For simple production deployments, use Gunicorn with the eventlet worker:

```bash
gunicorn -k eventlet -w 1 app:app
```

Adjust worker count based on CPU/memory. For larger scale, consider a
proper async worker pool and external message broker.

## Endpoints
- `GET /` - main UI
- `POST /upload` - upload one or more files (form field `files`, accepts `.log` and `.txt`). Returns JSON with aggregated counts.
- `GET /report` - downloads a PDF report for the last analyzed counts and security findings.

## Security dashboard
- Suspicious IP detection is based on repeated failed login attempts per IP.
- Brute-force detection flags bursts of failures within a short time window.
- Threat levels are shown as Normal, Suspicious, or Critical in the UI.
- Socket.IO emits `security_update` snapshots and `security_alert` events for live incident updates.
- The PDF report now includes suspicious IPs, threat summaries, and attack detections.

## Uploads folder
Uploaded files are saved under the `uploads/` directory next to the app.

## Socket.IO events
- Server emits `update_counts` with `{ counts: { ERROR, WARNING, INFO } }` when analyses complete.
- Server emits `new_log` events when a monitored file has appended lines.
- Client may request monitoring by emitting `monitor` with `{ filename: "TIMESTAMP_name.log" }` to start a background tail task.

## Notes & troubleshooting
- Max upload size is set to 16 MB in `app.py`.
- Filenames are sanitized using `secure_filename`.
- If you see issues with Socket.IO, ensure `eventlet` is installed and that you run with `python app.py` or `gunicorn -k eventlet`.

## Next steps (suggestions)
- Add unit tests for `analyser.count_levels` and `stats` helpers.
- Replace the simple poll-file tailer with `watchdog` for more efficient file system events.
