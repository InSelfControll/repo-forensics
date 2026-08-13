#!/usr/bin/env python3
"""session_json_wrap.py - Wrap SessionStart hook text output in a JSON envelope.

Kimi Code and Codex require SessionStart hook stdout to be valid JSON; plain
text fails with "hook returned invalid session start JSON output". Reads the
wrapped hook's output on stdin and emits the hookSpecificOutput envelope both
hosts accept (the same contract Claude Code documents for additionalContext).
Empty input produces no output, so silent hooks stay silent.
"""

import json
import sys

text = sys.stdin.read()
if text.strip():
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": text.rstrip(),
        }
    }))
