"""Main Flask application for Log Analyzer.

Provides upload handling, real-time updates via SocketIO and PDF report
generation. Implementation favors clarity and separation of concerns.
"""

import os
import json
import tempfile
from datetime import datetime
from io import BytesIO

from flask import Flask, render_template, request, jsonify, send_file, abort
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename

from analyser import count_levels
from report import generate_pdf_report
from monitor import tail_file_and_emit
from security import SecurityTracker
from stats import chart_data_from_counts, threat_chart_data_from_report
import threading


UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), "python-log-analyser-uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
STATE_FILE = os.path.join(UPLOAD_FOLDER, "last_report_state.json")

ALLOWED_EXTENSIONS = {"log", "txt"}


def allowed_filename(filename: str) -> bool:
    if not filename:
        return False
    name = filename.rsplit(".", 1)
    if len(name) == 2 and name[1].lower() in ALLOWED_EXTENSIONS:
        return True
    return False


def _resolve_uploaded_file_path(filename: str):
    if not filename:
        return None

    safe_name = secure_filename(filename)
    if not safe_name:
        return None

    upload_root = os.path.realpath(app.config["UPLOAD_FOLDER"])
    file_path = os.path.realpath(os.path.join(upload_root, safe_name))
    try:
        if os.path.commonpath([file_path, upload_root]) != upload_root:
            return None
    except Exception:
        return None

    if not os.path.exists(file_path):
        return None
    return file_path


app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit

# SocketIO init.
# Prefer eventlet when available (production) but fall back to threading for
# local/dev environments where eventlet may not be installed or desirable.
try:
    import eventlet  # type: ignore
    _async_mode = "eventlet"
except Exception:
    _async_mode = "threading"

socketio = SocketIO(app, cors_allowed_origins="*", async_mode=_async_mode)

# In-memory store for last computed counts (simple, acceptable for a small app)
app.config["LAST_COUNTS"] = {"ERROR": 0, "WARNING": 0, "INFO": 0}
app.config["LAST_SECURITY"] = {
    "threat_level": "Normal",
    "threat_counts": {"Normal": 0, "Suspicious": 0, "Critical": 0},
    "suspicious_ips": [],
    "brute_force_attacks": [],
    "alerts": [],
    "summary": {"total_lines": 0, "failed_attempts": 0, "unique_suspicious_ips": 0, "brute_force_events": 0, "error_lines": 0},
}
app.config["MONITOR_EVENTS"] = {}


def _load_last_state() -> None:
    """Load last analysis state from temp storage so reports survive server restarts."""
    try:
        if not os.path.exists(STATE_FILE):
            return
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            state = json.load(fh)

        counts = state.get("counts")
        security = state.get("security")
        if isinstance(counts, dict):
            app.config["LAST_COUNTS"] = {
                "ERROR": int(counts.get("ERROR", 0)),
                "WARNING": int(counts.get("WARNING", 0)),
                "INFO": int(counts.get("INFO", 0)),
            }
        if isinstance(security, dict):
            app.config["LAST_SECURITY"] = security
    except Exception:
        # Non-fatal; app can continue with empty defaults.
        return


def _persist_last_state(counts: dict, security: dict) -> None:
    """Persist last analysis state to temp storage for report consistency."""
    try:
        payload = {"counts": counts, "security": security}
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
    except Exception:
        # Non-fatal persistence failure.
        return


_load_last_state()


@app.route("/", methods=["GET"])
def index():
    """Render the main UI."""
    counts = app.config.get("LAST_COUNTS", {"ERROR": 0, "WARNING": 0, "INFO": 0})
    security_report = app.config.get("LAST_SECURITY", {})
    labels, data = chart_data_from_counts(counts)
    threat_labels, threat_data = threat_chart_data_from_report(security_report)
    return render_template(
        "index.html",
        labels=labels,
        data=data,
        threat_labels=threat_labels,
        threat_data=threat_data,
        counts=counts,
        security=security_report,
    )


@app.route("/upload", methods=["POST"])
def upload():
    """Handle one or more uploaded files and return aggregated counts as JSON.

    Expects files in form field `files` (multiple). Emits a SocketIO
    `update_counts` event so connected clients can update charts in real time.
    """
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files uploaded"}), 400

    aggregated = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    security_tracker = SecurityTracker()
    stored = []
    preview_lines = []

    for f in files:
        if not f or not f.filename:
            continue
        filename = secure_filename(f.filename)
        if not allowed_filename(filename):
            return jsonify({"error": f"File type not allowed: {filename}"}), 400

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved_name = f"{timestamp}_{filename}"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], saved_name)

        try:
            data = f.read()
            # decode safely for analysis
            text_lines = data.decode("utf-8", errors="ignore").splitlines()
            preview_lines.extend(text_lines[:50])
            counts = count_levels(text_lines)
            for k, v in counts.items():
                aggregated[k] = aggregated.get(k, 0) + v
            for line in text_lines:
                security_tracker.ingest(line)

            # persist to temporary OS storage so monitoring can still tail the file
            with open(save_path, "wb") as out:
                out.write(data)
            stored.append(saved_name)
        except Exception as exc:
            return jsonify({"error": f"Failed to process {filename}: {exc}"}), 500

    # update last known counts and notify clients
    app.config["LAST_COUNTS"] = aggregated
    socketio.emit("update_counts", {"counts": aggregated})

    security_report = security_tracker.snapshot()
    app.config["LAST_SECURITY"] = security_report
    _persist_last_state(aggregated, security_report)
    socketio.emit("security_update", security_report)
    for alert in security_report.get("alerts", []):
        socketio.emit("security_alert", alert)

    labels, data = chart_data_from_counts(aggregated)
    threat_labels, threat_data = threat_chart_data_from_report(security_report)
    return jsonify({
        "counts": aggregated,
        "labels": labels,
        "data": data,
        "threat_labels": threat_labels,
        "threat_data": threat_data,
        "security": security_report,
        "saved": stored,
        "preview_lines": preview_lines,
    }), 200


@app.route("/uploaded-file", methods=["GET", "POST"])
def uploaded_file():
    """Read or update a server-side uploaded copy stored in temporary space."""
    payload = request.get_json(silent=True) or request.form or request.args
    filename = payload.get("filename")
    file_path = _resolve_uploaded_file_path(filename)
    if not file_path:
        return jsonify({"error": "file_not_found"}), 404

    if request.method == "GET":
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            return jsonify({"filename": os.path.basename(file_path), "content": content}), 200
        except Exception as exc:
            return jsonify({"error": f"Failed to read uploaded copy: {exc}"}), 500

    content = payload.get("content", "")
    try:
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        text_lines = content.splitlines()
        counts = count_levels(text_lines)
        security_tracker = SecurityTracker()
        for line in text_lines:
            security_tracker.ingest(line)

        security_report = security_tracker.snapshot()
        app.config["LAST_COUNTS"] = counts
        app.config["LAST_SECURITY"] = security_report
        _persist_last_state(counts, security_report)
        socketio.emit("update_counts", {"counts": counts})
        socketio.emit("security_update", security_report)
        for alert in security_report.get("alerts", []):
            socketio.emit("security_alert", alert)

        labels, data = chart_data_from_counts(counts)
        threat_labels, threat_data = threat_chart_data_from_report(security_report)
        return jsonify({
            "filename": os.path.basename(file_path),
            "content": content,
            "counts": counts,
            "labels": labels,
            "data": data,
            "threat_labels": threat_labels,
            "threat_data": threat_data,
            "security": security_report,
            "preview_lines": text_lines[:50],
        }), 200
    except Exception as exc:
        return jsonify({"error": f"Failed to save uploaded copy: {exc}"}), 500


@app.route("/append-line", methods=["POST"])
def append_line():
    """Append one new line to a server-side uploaded copy and refresh analysis."""
    payload = request.get_json(silent=True) or {}
    filename = payload.get("filename")
    line = str(payload.get("line", "")).rstrip("\r\n")

    if not line.strip():
        return jsonify({"error": "line_required"}), 400

    file_path = _resolve_uploaded_file_path(filename)
    if not file_path:
        return jsonify({"error": "file_not_found"}), 404

    try:
        with open(file_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            text_lines = fh.read().splitlines()

        counts = count_levels(text_lines)
        security_tracker = SecurityTracker()
        for current_line in text_lines:
            security_tracker.ingest(current_line)

        security_report = security_tracker.snapshot()
        app.config["LAST_COUNTS"] = counts
        app.config["LAST_SECURITY"] = security_report
        _persist_last_state(counts, security_report)
        socketio.emit("update_counts", {"counts": counts})
        socketio.emit("security_update", security_report)
        for alert in security_report.get("alerts", []):
            socketio.emit("security_alert", alert)

        labels, data = chart_data_from_counts(counts)
        threat_labels, threat_data = threat_chart_data_from_report(security_report)
        return jsonify({
            "filename": os.path.basename(file_path),
            "line": line,
            "counts": counts,
            "labels": labels,
            "data": data,
            "threat_labels": threat_labels,
            "threat_data": threat_data,
            "security": security_report,
            "preview_lines": text_lines[-50:],
        }), 200
    except Exception as exc:
        return jsonify({"error": f"Failed to append line: {exc}"}), 500


@app.route("/report", methods=["GET"])
def report():
    """Return a PDF report based on the last computed counts."""
    counts = app.config.get("LAST_COUNTS", {"ERROR": 0, "WARNING": 0, "INFO": 0})
    security_report = app.config.get("LAST_SECURITY", {})
    try:
        pdf_bytes = generate_pdf_report(counts, security_report)
        response = send_file(
            BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name="log_report.pdf",
        )
        # Avoid stale PDF downloads from browser cache.
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    except Exception:
        abort(500)


@socketio.on("connect")
def handle_connect():
    # Send current counts to newly connected client
    socketio.emit("update_counts", {"counts": app.config.get("LAST_COUNTS", {})})
    socketio.emit("security_update", app.config.get("LAST_SECURITY", {}))


@socketio.on("monitor")
def handle_monitor_request(data):
    """Start tailing a file for a client. `data` should include `filename` stored in temporary OS storage.

    This starts a background task that emits `new_log` events for appended lines.
    """
    filename = (data or {}).get("filename")
    if not filename:
        return

    file_path = _resolve_uploaded_file_path(filename)
    if not file_path:
        socketio.emit("monitor_error", {"error": "file_not_found"})
        return

    sid = request.sid
    # Stop any existing monitor for this session (prevent duplicates)
    try:
        existing = app.config["MONITOR_EVENTS"].get(sid)
        if existing and not existing.is_set():
            existing.set()
    except Exception:
        pass

    # create a stop event for this background task and register it
    stop_event = threading.Event()
    app.config["MONITOR_EVENTS"][sid] = stop_event

    # Start background tailing task so the call returns quickly
    socketio.start_background_task(tail_file_and_emit, socketio, sid, file_path, "new_log", stop_event)


@socketio.on("stop_monitor")
def handle_stop_monitor(_data):
    sid = request.sid
    try:
        existing = app.config["MONITOR_EVENTS"].get(sid)
        if existing and not existing.is_set():
            existing.set()
            socketio.emit("monitor_stopped", {"message": "stopped"}, room=sid)
    except Exception:
        pass


if __name__ == "__main__":
    # Use socketio.run for proper Socket.IO support when running the
    # application directly. For production deployments on Render use
    # Gunicorn with the eventlet worker (see README / Render settings).
    port = int(os.environ.get("PORT", "10000"))
    socketio.run(app, debug=False, host="0.0.0.0", port=port)