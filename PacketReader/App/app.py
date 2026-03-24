from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import pty
import re
import select
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, File, Form, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

CONFIG_PATH = DATA_DIR / "config.json"
RULES_PATH_DEFAULT = DATA_DIR / "local.rules"
OUTPUT_DIR_DEFAULT = DATA_DIR / "output"
OUTPUT_DIR_DEFAULT.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "alerts.db"

PROCESS_LOG_MAX_LINES = 5000
LIVE_ALERT_CACHE_MAX = 1500

DEFAULT_RULES = """alert icmp any any -> any any (msg:"ICMP detected"; sid:1000001; rev:1;)
alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1000002; rev:1;)
alert tcp any any -> any 443 (msg:"HTTPS traffic detected"; sid:1000003; rev:1;)
"""

DEFAULT_CONFIG = {
    "snort_binary": "/usr/local/bin/snort",
    "rules_path": str(RULES_PATH_DEFAULT),
    "output_dir": str(OUTPUT_DIR_DEFAULT),
    "home_net": "any",
}

ALERT_LINE_RE = re.compile(
    r'^(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+"?(.*?)"?\s+\[\*\*\]\s+\[Priority:\s*(\d+)\]\s+\{([A-Z0-9_]+)\}\s+(.+?)\s+->\s+(.+)$'
)
FAST_RE = re.compile(r'\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+"?(.*?)"?\s+\[\*\*\]')


def severity_from_priority(priority: int) -> str:
    if priority <= 1:
        return "high"
    if priority == 2:
        return "medium"
    return "low"


class WSManager:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self.lock:
            self.clients.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self.lock:
            self.clients.discard(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        async with self.lock:
            clients = list(self.clients)

        dead: list[WebSocket] = []
        for ws in clients:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)

        if dead:
            async with self.lock:
                for ws in dead:
                    self.clients.discard(ws)


class EventBus:
    def __init__(self, ws_manager: WSManager) -> None:
        self.ws_manager = ws_manager
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    def publish_from_thread(self, message: dict[str, Any]) -> None:
        if self.loop is None:
            return
        try:
            self.loop.call_soon_threadsafe(self.queue.put_nowait, message)
        except Exception:
            pass

    async def publish(self, message: dict[str, Any]) -> None:
        await self.queue.put(message)

    async def run(self) -> None:
        while True:
            message = await self.queue.get()
            try:
                await self.ws_manager.broadcast(message)
            except Exception:
                pass


class AlertDB:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    timestamp_text TEXT NOT NULL,
                    gid TEXT,
                    sid TEXT,
                    rev TEXT,
                    msg TEXT,
                    priority INTEGER,
                    severity TEXT,
                    protocol TEXT,
                    src TEXT,
                    dst TEXT,
                    raw_line TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sid ON alerts(sid)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dst ON alerts(dst)")
            conn.commit()
        finally:
            conn.close()

    def insert_alert(self, alert: dict[str, Any]) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO alerts (
                    ts, timestamp_text, gid, sid, rev, msg, priority, severity,
                    protocol, src, dst, raw_line
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.get("ts", time.time()),
                    alert.get("timestamp", ""),
                    alert.get("gid", ""),
                    alert.get("sid", ""),
                    alert.get("rev", ""),
                    alert.get("text", ""),
                    alert.get("priority", 0),
                    alert.get("severity", "low"),
                    alert.get("protocol", ""),
                    alert.get("src", ""),
                    alert.get("dst", ""),
                    alert.get("raw_line", ""),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def search_alerts(
        self,
        limit: int = 100,
        text: str = "",
        sid: str = "",
        src: str = "",
        dst: str = "",
    ) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            query = "SELECT * FROM alerts WHERE 1=1"
            params: list[Any] = []

            if text:
                query += " AND (msg LIKE ? OR raw_line LIKE ?)"
                params.extend([f"%{text}%", f"%{text}%"])
            if sid:
                query += " AND sid LIKE ?"
                params.append(f"%{sid}%")
            if src:
                query += " AND src LIKE ?"
                params.append(f"%{src}%")
            if dst:
                query += " AND dst LIKE ?"
                params.append(f"%{dst}%")

            query += " ORDER BY ts DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def count_alerts(self) -> int:
        conn = self._connect()
        try:
            row = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()
            return int(row["c"])
        finally:
            conn.close()

    def top_sids(self, limit: int = 10) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT sid, msg, COUNT(*) AS hits
                FROM alerts
                GROUP BY sid, msg
                ORDER BY hits DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def top_sources(self, limit: int = 10) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT src, COUNT(*) AS hits
                FROM alerts
                WHERE src != ''
                GROUP BY src
                ORDER BY hits DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def severity_counts(self) -> dict[str, int]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS hits
                FROM alerts
                GROUP BY severity
                """
            ).fetchall()
            out = {"high": 0, "medium": 0, "low": 0}
            for r in rows:
                out[r["severity"]] = int(r["hits"])
            return out
        finally:
            conn.close()

    def last_alert(self) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT 1").fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def clear_alerts(self) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM alerts")
            conn.commit()
        finally:
            conn.close()


class SnortManager:
    def __init__(self, event_bus: EventBus) -> None:
        self.process: subprocess.Popen[bytes] | None = None
        self.process_lock = threading.Lock()
        self.process_log_lines: list[str] = []
        self.alert_cache: list[dict[str, Any]] = []
        self.current_command: list[str] = []
        self.current_alert_mode: str | None = None
        self.current_inline_mode: bool = False
        self.current_iface: str | None = None
        self.current_bpf_filter: str | None = None
        self.reader_thread: threading.Thread | None = None
        self.last_alert_file: Path | None = None
        self.last_uploaded_pcap: Path | None = None
        self.last_bpf_file: Path | None = None
        self.started_at: float | None = None
        self.last_activity_ts: float | None = None
        self.last_heartbeat_ts: float = time.time()
        self.heartbeat_counter: int = 0
        self._pty_master_fd: int | None = None

        self.config = self._load_config()
        self.db = AlertDB(DB_PATH)
        self.event_bus = event_bus
        self._ensure_files()

    def _ensure_files(self) -> None:
        rules_path = Path(self.config["rules_path"])
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        if not rules_path.exists():
            rules_path.write_text(DEFAULT_RULES, encoding="utf-8")

        out_dir = Path(self.config["output_dir"])
        out_dir.mkdir(parents=True, exist_ok=True)

    def _load_config(self) -> dict[str, Any]:
        if CONFIG_PATH.exists():
            try:
                return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
        return DEFAULT_CONFIG.copy()

    def save_config(self, updates: dict[str, Any]) -> dict[str, Any]:
        self.config.update({
            "snort_binary": updates.get("snort_binary", self.config["snort_binary"]) or self.config["snort_binary"],
            "rules_path": updates.get("rules_path", self.config["rules_path"]) or self.config["rules_path"],
            "output_dir": updates.get("output_dir", self.config["output_dir"]) or self.config["output_dir"],
            "home_net": updates.get("home_net", self.config.get("home_net", "any")) or "any",
        })
        self._ensure_files()
        CONFIG_PATH.write_text(json.dumps(self.config, indent=2), encoding="utf-8")
        return self.config

    def get_rules_text(self) -> str:
        rules_path = Path(self.config["rules_path"])
        if not rules_path.exists():
            return ""
        return rules_path.read_text(encoding="utf-8", errors="ignore")

    def save_rules_text(self, rules_text: str) -> None:
        rules_path = Path(self.config["rules_path"])
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        rules_path.write_text(rules_text, encoding="utf-8")

    def _logger_filename(self, alert_mode: str) -> Path:
        base = Path(self.config["output_dir"])
        mapping = {
            "alert_json": base / "alert_json.txt",
            "alert_csv": base / "alert_csv.txt",
            "alert_full": base / "alert_full.txt",
            "alert_fast": base / "alert_fast.txt",
        }
        return mapping.get(alert_mode, base / f"{alert_mode}.txt")

    def _build_base_command(self, alert_mode: str, quiet: bool) -> list[str]:
        cmd: list[str] = []
        stdbuf = shutil.which("stdbuf")
        if stdbuf:
            cmd += [stdbuf, "-oL", "-eL"]

        cmd += [self.config["snort_binary"]]

        rules_path = Path(self.config["rules_path"])
        out_dir = Path(self.config["output_dir"])
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd += ["-R", str(rules_path)]
        cmd += ["-A", alert_mode]
        cmd += ["-l", str(out_dir)]

        home_net = self.config.get("home_net", "")
        if home_net and home_net != "any":
            cmd += ["-H", home_net]

        if quiet:
            cmd += ["-q"]

        return cmd

    def build_live_command(
        self,
        iface: str,
        bpf_filter: str | None,
        alert_mode: str,
        inline_mode: bool,
        quiet: bool,
        daq: str | None,
        daq_dir: str | None,
    ) -> list[str]:
        cmd = self._build_base_command(alert_mode, quiet)
        cmd += ["-i", iface]

        if bpf_filter:
            cmd += ["-F", str(self._write_temp_bpf_filter(bpf_filter))]

        if inline_mode:
            cmd += ["-Q"]

        if daq:
            cmd += ["--daq", daq]

        if daq_dir:
            cmd += ["--daq-dir", daq_dir]

        return cmd

    def build_pcap_command(self, pcap_path: str, alert_mode: str, quiet: bool) -> list[str]:
        cmd = self._build_base_command(alert_mode, quiet)
        cmd += ["-r", pcap_path]
        return cmd

    def _write_temp_bpf_filter(self, bpf_filter: str) -> str:
        if self.last_bpf_file and self.last_bpf_file.exists():
            try:
                self.last_bpf_file.unlink()
            except Exception:
                pass

        fd, path = tempfile.mkstemp(prefix="snort_bpf_", suffix=".txt")
        os.close(fd)
        p = Path(path)
        p.write_text(bpf_filter, encoding="utf-8")
        self.last_bpf_file = p
        return path

    def _publish(self, message: dict[str, Any]) -> None:
        self.event_bus.publish_from_thread(message)

    def _mark_activity(self) -> None:
        self.last_activity_ts = time.time()

    def _append_log(self, line: str) -> None:
        line = line.rstrip("\r").rstrip("\n")
        if not line:
            return

        self.process_log_lines.append(line)
        if len(self.process_log_lines) > PROCESS_LOG_MAX_LINES:
            self.process_log_lines = self.process_log_lines[-PROCESS_LOG_MAX_LINES:]

        self._mark_activity()
        self._publish({"type": "log_line", "line": line})

        parsed = self._parse_alert_line(line)
        if parsed:
            self.alert_cache.append(parsed)
            if len(self.alert_cache) > LIVE_ALERT_CACHE_MAX:
                self.alert_cache = self.alert_cache[-LIVE_ALERT_CACHE_MAX:]
            self.db.insert_alert(parsed)
            self._publish({"type": "alert", "alert": parsed})
            self._publish({"type": "status", "status": self.status()})
            self._publish({"type": "dashboard", "dashboard": self.dashboard_data()})

    def _parse_alert_line(self, line: str) -> dict[str, Any] | None:
        line = line.strip()
        if not line:
            return None

        m = ALERT_LINE_RE.search(line)
        if m:
            ts_text, gid, sid, rev, text, priority, protocol, src, dst = m.groups()
            prio = int(priority)
            return {
                "ts": time.time(),
                "timestamp": ts_text,
                "level": "alert",
                "gid": gid,
                "sid": sid,
                "rev": rev,
                "priority": prio,
                "severity": severity_from_priority(prio),
                "protocol": protocol,
                "src": src,
                "dst": dst,
                "text": text.strip(),
                "raw_line": line,
            }

        m = FAST_RE.search(line)
        if m:
            gid, sid, rev, text = m.groups()
            return {
                "ts": time.time(),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "level": "alert",
                "gid": gid,
                "sid": sid,
                "rev": rev,
                "priority": 0,
                "severity": "low",
                "protocol": "",
                "src": "",
                "dst": "",
                "text": text.strip(),
                "raw_line": line,
            }

        return None

    def _reader(self) -> None:
        master_fd = self._pty_master_fd
        if self.process is None or master_fd is None:
            return

        buffer = b""

        try:
            while True:
                if self.process.poll() is not None:
                    while True:
                        r, _, _ = select.select([master_fd], [], [], 0)
                        if not r:
                            break
                        chunk = os.read(master_fd, 4096)
                        if not chunk:
                            break
                        buffer += chunk
                    break

                r, _, _ = select.select([master_fd], [], [], 0.2)
                if not r:
                    continue

                chunk = os.read(master_fd, 4096)
                if not chunk:
                    continue

                buffer += chunk

                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    try:
                        decoded = line.decode("utf-8", errors="ignore")
                    except Exception:
                        decoded = str(line)
                    self._append_log(decoded)

            if buffer:
                try:
                    decoded = buffer.decode("utf-8", errors="ignore")
                except Exception:
                    decoded = str(buffer)
                if decoded.strip():
                    self._append_log(decoded)

        except Exception as exc:
            self._append_log(f"[reader error] {exc}")
        finally:
            try:
                os.close(master_fd)
            except Exception:
                pass
            self._pty_master_fd = None

        rc = self.process.poll()
        self._append_log(f"[process exited with code {rc}]")
        self._publish({"type": "status", "status": self.status()})

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start_command(
        self,
        cmd: list[str],
        alert_mode: str,
        inline_mode: bool,
        iface: str | None = None,
        bpf_filter: str | None = None,
    ) -> tuple[bool, str]:
        with self.process_lock:
            if self.is_running():
                return False, "Snort is already running."

            self.process_log_lines.clear()
            self.alert_cache.clear()
            self.current_command = cmd
            self.current_alert_mode = alert_mode
            self.current_inline_mode = inline_mode
            self.current_iface = iface
            self.current_bpf_filter = bpf_filter
            self.last_alert_file = self._logger_filename(alert_mode)
            self.started_at = time.time()
            self.last_activity_ts = self.started_at

            try:
                master_fd, slave_fd = pty.openpty()

                self.process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    text=False,
                    cwd=str(APP_DIR),
                    close_fds=True,
                )

                os.close(slave_fd)
                self._pty_master_fd = master_fd

            except FileNotFoundError:
                return False, f"Snort binary not found: {self.config['snort_binary']}"
            except Exception as exc:
                return False, f"Failed to start Snort: {exc}"

            self.reader_thread = threading.Thread(target=self._reader, daemon=True)
            self.reader_thread.start()
            self._publish({"type": "status", "status": self.status()})
            return True, "Snort started."

    def stop(self) -> tuple[bool, str]:
        with self.process_lock:
            if not self.is_running():
                return False, "Snort is not running."

            assert self.process is not None
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass

            try:
                if self._pty_master_fd is not None:
                    os.close(self._pty_master_fd)
            except Exception:
                pass
            self._pty_master_fd = None

            self._publish({"type": "status", "status": self.status()})
            return True, "Snort stopped."

    def clear_logs(self) -> None:
        self.process_log_lines.clear()
        self.alert_cache.clear()
        self._publish({"type": "logs_cleared"})

    def status(self) -> dict[str, Any]:
        pid = self.process.pid if self.is_running() and self.process else None
        uptime = int(time.time() - self.started_at) if self.is_running() and self.started_at else 0
        sev = self.db.severity_counts()
        last_alert = self.db.last_alert()
        return {
            "running": self.is_running(),
            "pid": pid,
            "command": " ".join(self.current_command) if self.current_command else "",
            "alert_mode": self.current_alert_mode,
            "inline_mode": self.current_inline_mode,
            "iface": self.current_iface,
            "bpf_filter": self.current_bpf_filter,
            "uptime_seconds": uptime,
            "alert_count_total": self.db.count_alerts(),
            "severity_counts": sev,
            "last_activity_ts": self.last_activity_ts,
            "last_heartbeat_ts": self.last_heartbeat_ts,
            "last_alert_ts": last_alert["ts"] if last_alert else None,
            "heartbeat_counter": self.heartbeat_counter,
        }

    def dashboard_data(self) -> dict[str, Any]:
        return {
            "top_sids": self.db.top_sids(10),
            "top_sources": self.db.top_sources(10),
            "severity_counts": self.db.severity_counts(),
            "alert_count_total": self.db.count_alerts(),
            "last_alert": self.db.last_alert(),
        }

    def get_logs(self) -> dict[str, Any]:
        preview = ""
        if self.last_alert_file and self.last_alert_file.exists():
            try:
                preview = self.last_alert_file.read_text(encoding="utf-8", errors="ignore")[-8000:]
            except Exception:
                preview = ""

        return {
            "process_log": "\n".join(self.process_log_lines[-120:]),
            "alert_file_preview": preview,
        }

    async def heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(1)
            self.last_heartbeat_ts = time.time()
            self.heartbeat_counter += 1
            await self.event_bus.publish({
                "type": "heartbeat",
                "heartbeat": {
                    "ts": self.last_heartbeat_ts,
                    "running": self.is_running(),
                    "heartbeat_counter": self.heartbeat_counter,
                    "uptime_seconds": int(time.time() - self.started_at) if self.is_running() and self.started_at else 0,
                    "iface": self.current_iface,
                    "last_activity_ts": self.last_activity_ts,
                }
            })
            await self.event_bus.publish({"type": "status", "status": self.status()})


ws_manager = WSManager()
event_bus = EventBus(ws_manager)
manager = SnortManager(event_bus)
app = FastAPI(title="Snort Web Console Pro Live")


@app.on_event("startup")
async def on_startup() -> None:
    event_bus.set_loop(asyncio.get_running_loop())
    asyncio.create_task(event_bus.run())
    asyncio.create_task(manager.heartbeat_loop())


@app.get("/", response_class=HTMLResponse)
def root() -> HTMLResponse:
    html = (APP_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({"type": "status", "status": manager.status()})
        await websocket.send_json({"type": "dashboard", "dashboard": manager.dashboard_data()})
        await websocket.send_json({"type": "logs_snapshot", "logs": manager.get_logs()})
        await websocket.send_json({"type": "alerts_snapshot", "alerts": manager.db.search_alerts(limit=100)})

        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        await ws_manager.disconnect(websocket)


@app.get("/api/status")
def api_status() -> dict[str, Any]:
    return manager.status()


@app.get("/api/config")
def api_config() -> dict[str, Any]:
    return manager.config


@app.post("/api/config")
def api_config_save(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    cfg = manager.save_config(payload)
    return {"ok": True, "message": "Config saved.", **cfg}


@app.get("/api/rules")
def api_rules() -> dict[str, Any]:
    return {"rules_text": manager.get_rules_text()}


@app.post("/api/rules")
def api_rules_save(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    manager.save_rules_text(payload.get("rules_text", ""))
    return {"ok": True, "message": "Rules saved."}


@app.get("/api/logs")
def api_logs() -> dict[str, Any]:
    return manager.get_logs()


@app.post("/api/logs/clear")
def api_logs_clear() -> dict[str, Any]:
    manager.clear_logs()
    return {"ok": True, "message": "Captured logs cleared."}


@app.get("/api/alerts")
def api_alerts(
    limit: int = Query(100, ge=1, le=1000),
    text: str = "",
    sid: str = "",
    src: str = "",
    dst: str = "",
) -> dict[str, Any]:
    return {"alerts": manager.db.search_alerts(limit=limit, text=text, sid=sid, src=src, dst=dst)}


@app.get("/api/dashboard")
def api_dashboard() -> dict[str, Any]:
    return manager.dashboard_data()


@app.post("/api/alerts/clear")
def api_alerts_clear() -> dict[str, Any]:
    manager.db.clear_alerts()
    return {"ok": True, "message": "Alert history cleared."}


@app.get("/api/alerts.csv")
def api_alerts_csv(
    text: str = "",
    sid: str = "",
    src: str = "",
    dst: str = "",
) -> StreamingResponse:
    rows = manager.db.search_alerts(limit=5000, text=text, sid=sid, src=src, dst=dst)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["timestamp", "gid", "sid", "rev", "priority", "severity", "protocol", "src", "dst", "msg"])
    for r in rows:
        writer.writerow([
            r.get("timestamp_text", ""),
            r.get("gid", ""),
            r.get("sid", ""),
            r.get("rev", ""),
            r.get("priority", ""),
            r.get("severity", ""),
            r.get("protocol", ""),
            r.get("src", ""),
            r.get("dst", ""),
            r.get("msg", ""),
        ])
    out.seek(0)
    return StreamingResponse(
        out,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"},
    )


@app.post("/api/preview/live")
def api_preview_live(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    cmd = manager.build_live_command(
        iface=payload.get("iface", ""),
        bpf_filter=payload.get("bpf_filter") or None,
        alert_mode=payload.get("alert_mode", "alert_fast"),
        inline_mode=bool(payload.get("inline_mode", False)),
        quiet=bool(payload.get("quiet", False)),
        daq=payload.get("daq") or None,
        daq_dir=payload.get("daq_dir") or None,
    )
    return {"command": " ".join(cmd)}


@app.post("/api/run/live")
def api_run_live(payload: dict[str, Any] = Body(...)) -> JSONResponse:
    iface = (payload.get("iface") or "").strip()
    if not iface:
        return JSONResponse({"ok": False, "message": "Interface is required."}, status_code=400)

    cmd = manager.build_live_command(
        iface=iface,
        bpf_filter=payload.get("bpf_filter") or None,
        alert_mode=payload.get("alert_mode", "alert_fast"),
        inline_mode=bool(payload.get("inline_mode", False)),
        quiet=bool(payload.get("quiet", False)),
        daq=payload.get("daq") or None,
        daq_dir=payload.get("daq_dir") or None,
    )
    ok, msg = manager.start_command(
        cmd=cmd,
        alert_mode=payload.get("alert_mode", "alert_fast"),
        inline_mode=bool(payload.get("inline_mode", False)),
        iface=iface,
        bpf_filter=payload.get("bpf_filter") or None,
    )
    return JSONResponse({"ok": ok, "message": msg, "command": " ".join(cmd)}, status_code=200 if ok else 400)


@app.post("/api/run/stop")
def api_run_stop() -> JSONResponse:
    ok, msg = manager.stop()
    return JSONResponse({"ok": ok, "message": msg}, status_code=200 if ok else 400)


@app.post("/api/run/pcap")
async def api_run_pcap(
    file: UploadFile = File(...),
    alert_mode: str = Form("alert_fast"),
    quiet: str = Form("false"),
) -> JSONResponse:
    if manager.is_running():
        return JSONResponse({"ok": False, "message": "Stop current Snort process first."}, status_code=400)

    suffix = Path(file.filename or "upload.pcap").suffix or ".pcap"
    fd, tmp_path = tempfile.mkstemp(prefix="snort_upload_", suffix=suffix)
    os.close(fd)

    try:
        with open(tmp_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        manager.last_uploaded_pcap = Path(tmp_path)
        cmd = manager.build_pcap_command(
            pcap_path=tmp_path,
            alert_mode=alert_mode,
            quiet=(quiet == "true"),
        )
        ok, msg = manager.start_command(
            cmd=cmd,
            alert_mode=alert_mode,
            inline_mode=False,
            iface="pcap",
            bpf_filter=None,
        )
        return JSONResponse({"ok": ok, "message": msg, "command": " ".join(cmd)}, status_code=200 if ok else 400)
    except Exception as exc:
        return JSONResponse({"ok": False, "message": f"Failed to run pcap: {exc}"}, status_code=400)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")