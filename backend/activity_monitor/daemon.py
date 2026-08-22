"""
Activity Monitor Daemon — Phase 15
Background asyncio task that tracks application/process launches and closures
using psutil. Logs events into the activity_logs SQLite table.
"""

import asyncio
import psutil
from datetime import datetime, timezone, timedelta
from db import get_db
from logger import log_event

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
monitor_task = None
_previous_snapshot = {}  # {pid: {"name": ..., "username": ..., "cmdline": ..., "create_time": ...}}

# Processes to ignore (noise filtering)
IGNORED_NAMES = frozenset([
    # Kernel / system
    "kworker", "migration", "ksoftirqd", "rcu_sched", "rcu_bh",
    "watchdog", "kthreadd", "kdevtmpfs", "netns", "khungtaskd",
    "writeback", "kcompactd", "oom_reaper", "kblockd", "kswapd",
    "ecryptfs", "crypto", "kintegrityd", "kgamepad", "irq",
    # LogVigil's own processes
    "uvicorn",
    # Common transient system processes
    "dbus-daemon", "at-spi-bus-launcher", "at-spi2-registryd",
    "xdg-permission-store", "xdg-document-portal", "xdg-desktop-portal",
    "pipewire", "pipewire-pulse", "wireplumber",
])

IGNORED_PREFIXES = (
    "kworker", "migration/", "ksoftirqd/", "rcu_", "watchdog/", "irq/", 
    "jbd2/", "scsi_", "nvme", "mm_percpu", "cpuhp/", "kblockd", "kswapd",
    "kintegrityd", "kgamepad", "systemd-", "dbus-", "gmain", "gdbus"
)

MIN_PID = 100  # Skip kernel/early system PIDs


def _normalize_process_name(name: str, cmdline_parts: list) -> str:
    """
    Normalize raw process names and Linux worker threads into clean,
    human-readable application identities.
    """
    cmdline_str = " ".join(cmdline_parts).lower()
    name_lower = name.lower()

    # Firefox / Firefox ESR / Snap / Flatpak / Multi-process tabs
    if any(k in name_lower for k in [
        "firefox", "isolated servic", "isolated web co", "web content", 
        "geckomain", "rdd process", "socket process", "privileged cont"
    ]) or "firefox" in cmdline_str:
        if any(tab_sig in cmdline_str for tab_sig in ["-contentproc", "tab", "isolated"]):
            return "Firefox (Web Tab)"
        return "Firefox"

    # Google Chrome / Chromium / Brave
    if "brave" in name_lower or "brave" in cmdline_str:
        return "Brave Browser"
    if "chrome" in name_lower or "chromium" in name_lower or "google-chrome" in cmdline_str:
        if "--type=renderer" in cmdline_str or "tab" in cmdline_str:
            return "Chrome (Web Tab)"
        elif "--type=extension" in cmdline_str:
            return "Chrome (Extension)"
        return "Google Chrome"

    # Microsoft Edge
    if "msedge" in name_lower or "edge" in cmdline_str:
        return "Microsoft Edge"

    # Development Editors
    if name_lower in ["code", "codium", "code-oss"] or "vscode" in cmdline_str:
        return "VS Code"
    if name_lower in ["sublime_text", "subl"]:
        return "Sublime Text"
    if name_lower in ["pycharm", "pycharm.sh"]:
        return "PyCharm"
    if name_lower in ["atom"]:
        return "Atom"
    if name_lower in ["vim", "nvim", "nano", "gedit", "kate"]:
        return f"Editor ({name})"

    # Shells & Terminals
    if name_lower in ["bash", "zsh", "sh", "fish", "dash"]:
        return f"Terminal ({name})"
    if name_lower in ["gnome-terminal-server", "konsole", "alacritty", "kitty", "xterm", "tilix", "terminator"]:
        return "Terminal"

    # System & Utilities
    if name_lower in ["nautilus", "thunar", "dolphin", "nemo", "pcmanfm"]:
        return "File Manager"
    if name_lower in ["vlc", "mpv", "totem"]:
        return "Media Player"
    if name_lower in ["spotify"]:
        return "Spotify"
    if name_lower in ["discord", "telegram-desktop", "slack", "signal-desktop"]:
        return name.capitalize()

    return name


def _is_ignored(name: str, pid: int, cmdline_parts: list) -> bool:
    """Check if a process should be filtered out from activity logging."""
    if pid < MIN_PID:
        return True
    name_lower = name.lower()
    # Ignore kernel threads (names in brackets)
    if name_lower.startswith("[") and name_lower.endswith("]"):
        return True
    # Ignore kernel prefix patterns
    if any(name_lower.startswith(prefix) for prefix in IGNORED_PREFIXES):
        return True
    # Ignore known noise processes
    if name_lower in IGNORED_NAMES:
        return True
    # Ignore python processes running this very app
    if name_lower in ("python", "python3"):
        cmdline_str = " ".join(cmdline_parts).lower()
        if "main.py" in cmdline_str or "uvicorn" in cmdline_str:
            return True
    return False


def get_process_snapshot() -> dict:
    """
    Capture a snapshot of all currently running processes.
    Returns {pid: {name, username, cmdline, create_time}}
    Uses psutil.process_iter with only needed attributes for minimal overhead.
    """
    snapshot = {}
    attrs = ["pid", "name", "username", "cmdline", "create_time"]
    for proc in psutil.process_iter(attrs=attrs, ad_value=None):
        try:
            info = proc.info
            pid = info["pid"]
            name = info["name"] or ""
            cmdline = info["cmdline"] or []
            if _is_ignored(name, pid, cmdline):
                continue
            normalized_name = _normalize_process_name(name, cmdline)
            snapshot[pid] = {
                "name": normalized_name,
                "username": info["username"] or "unknown",
                "cmdline": " ".join(cmdline)[:500],  # Cap command line length
                "create_time": info["create_time"],
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return snapshot


def diff_snapshots(old_snap: dict, new_snap: dict):
    """
    Compare two process snapshots and return (opened, closed) lists.
    Each item is a dict with process info.
    """
    old_pids = set(old_snap.keys())
    new_pids = set(new_snap.keys())

    opened = []
    for pid in new_pids - old_pids:
        info = new_snap[pid]
        opened.append({
            "pid": pid,
            "name": info["name"],
            "username": info["username"],
            "cmdline": info["cmdline"],
        })

    closed = []
    for pid in old_pids - new_pids:
        info = old_snap[pid]
        closed.append({
            "pid": pid,
            "name": info["name"],
            "username": info["username"],
            "cmdline": info["cmdline"],
        })

    return opened, closed


def _get_poll_interval() -> int:
    """Read polling interval from system_settings, default 5 seconds."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM system_settings WHERE key = 'activity_poll_interval'")
        row = cursor.fetchone()
        conn.close()
        if row:
            val = int(row["value"])
            return max(2, min(val, 60))  # Clamp between 2-60 seconds
        return 5
    except Exception:
        return 5


def _cleanup_old_logs(days: int = 30):
    """Delete activity logs older than N days to prevent unbounded growth."""
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM activity_logs WHERE timestamp < ?", (cutoff,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        if deleted > 0:
            log_event("INFO", f"Activity Monitor: auto-cleaned {deleted} log(s) older than {days} days.")
    except Exception as e:
        log_event("WARNING", f"Activity Monitor: cleanup failed: {str(e)}")


def _batch_insert_events(events: list):
    """Insert a batch of activity events in a single transaction."""
    if not events:
        return
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.executemany(
            "INSERT INTO activity_logs (timestamp, event_type, target, details, pid, username) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            events
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log_event("WARNING", f"Activity Monitor: failed to write events: {str(e)}")


async def _monitor_loop():
    """
    Main monitoring loop. Polls process list every N seconds,
    detects new (opened) and gone (closed) processes, and logs them.
    """
    global _previous_snapshot

    log_event("INFO", "Activity Monitor daemon started.")
    _cleanup_old_logs(30)

    # Take initial snapshot (don't log everything already running)
    _previous_snapshot = get_process_snapshot()
    # Wait two poll cycles before first diff to avoid logging all existing processes
    poll_interval = _get_poll_interval()
    await asyncio.sleep(poll_interval)

    while True:
        try:
            poll_interval = _get_poll_interval()

            # Check if monitoring is still enabled
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM system_settings WHERE key = 'activity_monitor_enabled'")
            row = cursor.fetchone()
            conn.close()
            if row and row["value"].lower() != "true":
                # Monitoring was disabled, sleep and re-check
                await asyncio.sleep(5)
                continue

            current_snapshot = get_process_snapshot()
            opened, closed = diff_snapshots(_previous_snapshot, current_snapshot)

            now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            batch = []

            for proc in opened:
                details = f"PID:{proc['pid']} CMD:{proc['cmdline']}" if proc["cmdline"] else f"PID:{proc['pid']}"
                batch.append((
                    now_iso,
                    "APP_OPENED",
                    proc["name"],
                    details,
                    proc["pid"],
                    proc["username"],
                ))

            for proc in closed:
                details = f"PID:{proc['pid']} CMD:{proc['cmdline']}" if proc["cmdline"] else f"PID:{proc['pid']}"
                batch.append((
                    now_iso,
                    "APP_CLOSED",
                    proc["name"],
                    details,
                    proc["pid"],
                    proc["username"],
                ))

            if batch:
                _batch_insert_events(batch)

            _previous_snapshot = current_snapshot
            await asyncio.sleep(poll_interval)

        except asyncio.CancelledError:
            log_event("INFO", "Activity Monitor daemon stopped.")
            break
        except Exception as e:
            log_event("WARNING", f"Activity Monitor loop error: {str(e)}")
            await asyncio.sleep(10)


def start_activity_monitor():
    """Start the activity monitor background task if monitoring is enabled."""
    global monitor_task
    # Check if enabled in settings
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM system_settings WHERE key = 'activity_monitor_enabled'")
        row = cursor.fetchone()
        conn.close()
        if not row or row["value"].lower() != "true":
            log_event("INFO", "Activity Monitor is disabled. Skipping daemon startup.")
            return
    except Exception:
        return

    if monitor_task is None or monitor_task.done():
        monitor_task = asyncio.create_task(_monitor_loop())


def stop_activity_monitor():
    """Stop the activity monitor background task."""
    global monitor_task
    if monitor_task and not monitor_task.done():
        monitor_task.cancel()


def is_monitor_running() -> bool:
    """Check if the monitor task is currently active."""
    return monitor_task is not None and not monitor_task.done()


def force_start_monitor():
    """Force-start the monitor regardless of current settings (used by toggle endpoint)."""
    global monitor_task
    if monitor_task is None or monitor_task.done():
        monitor_task = asyncio.create_task(_monitor_loop())


def force_stop_monitor():
    """Force-stop the monitor (used by toggle endpoint)."""
    global monitor_task, _previous_snapshot
    if monitor_task and not monitor_task.done():
        monitor_task.cancel()
    _previous_snapshot = {}
