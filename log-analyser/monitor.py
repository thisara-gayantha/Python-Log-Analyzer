"""Real-time monitoring helpers using Flask-SocketIO.

This module provides a simple tail-like monitor that reads appended lines
from a file and emits SocketIO events. It is intentionally lightweight
and suitable for small-to-medium scale monitoring.
"""

import os

from security import SecurityTracker




def tail_file_and_emit(socketio, sid: str, file_path: str, emit_event: str = "new_log", stop_event=None):
    """Tail a file and emit new lines to the client session `sid`.

    This function blocks; call it in a background task.
    Emits `emit_event` with payload { 'line': str, 'level': str }
    """
    try:
        tracker = SecurityTracker()
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            fh.seek(0, os.SEEK_END)
            while True:
                # allow external stop signal
                if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
                    # notify client that monitoring stopped
                    try:
                        socketio.emit("monitor_stopped", {"message": "stopped"}, room=sid)
                    except Exception:
                        pass
                    break

                where = fh.tell()
                line = fh.readline()
                if not line:
                    # Yield to the Socket.IO async model so other requests (e.g., /report) are not blocked.
                    socketio.sleep(0.5)
                    fh.seek(where)
                    continue

                socketio.emit(emit_event, {"line": line}, room=sid)
                alerts = tracker.ingest(line)
                if alerts:
                    for alert in alerts:
                        socketio.emit("security_alert", alert, room=sid)
                socketio.emit("security_update", tracker.snapshot(), room=sid)
    except Exception:
        # On any failure, stop tailing quietly (server shouldn't crash for client errors)
        return
