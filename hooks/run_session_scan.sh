#!/usr/bin/env bash
# Wrapper for SessionStart session_scan.py — same safety pattern as the
# other hook wrappers.
#
# SessionStart hooks should NEVER prevent a session from starting.
# If session_scan.py is missing, we log a warning and exit cleanly.

set -u

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-${KIMI_PLUGIN_ROOT:-}}"
SCRIPT="$PLUGIN_ROOT/skills/repo-forensics/scripts/session_scan.py"
LAUNCHER="$PLUGIN_ROOT/hooks/python-launcher.sh"
ENSURE_REFRESH="$PLUGIN_ROOT/hooks/ensure_refresh_daemon.sh"
JSON_WRAP="$PLUGIN_ROOT/hooks/session_json_wrap.py"

# Bootstrap or repair the background updater before checking freshness. This
# stays silent and never blocks SessionStart if the platform scheduler fails.
if [ -f "$ENSURE_REFRESH" ]; then
    "${BASH:-$(command -v bash || echo /bin/bash)}" "$ENSURE_REFRESH" || true
fi

if [ ! -f "$SCRIPT" ]; then
    echo "[repo-forensics] WARNING: session_scan.py not found at: $SCRIPT"
    echo "[repo-forensics] Session security scan disabled. Update or reinstall repo-forensics."
    exit 0
fi

if [ -f "$LAUNCHER" ]; then
    if [ -f "$JSON_WRAP" ]; then
        # SessionStart stdout must be a JSON envelope on Kimi Code and Codex
        # ("invalid session start JSON output" on plain text); the
        # hookSpecificOutput envelope is also the documented additionalContext
        # contract on Claude Code, so always wrap instead of host-sniffing.
        # stderr stays stderr; empty output stays silent.
        "${BASH:-$(command -v bash || echo /bin/bash)}" "$LAUNCHER" "$SCRIPT" \
            | "${BASH:-$(command -v bash || echo /bin/bash)}" "$LAUNCHER" "$JSON_WRAP"
        exit 0
    fi
    exec "${BASH:-$(command -v bash || echo /bin/bash)}" "$LAUNCHER" "$SCRIPT"
fi

if [ -f "$JSON_WRAP" ]; then
    python3 "$SCRIPT" | python3 "$JSON_WRAP"
    exit 0
fi

exec python3 "$SCRIPT"
