"""_context_gate.py - deterministic file/line context classifier.

Shared, per-consumer-policy gating primitive (v2.13.1). Extends the existing
evidence model (forensics_core.EVIDENCE_CLASSES / apply_evidence_caps) with
structural context signals so a scanner can set ``evidence_class="inferred"``
on findings whose carrier context is prose / test-fixture / blocklist, and let
the existing report-layer cap do the demotion (visible, auditable, fail-loud).

Design: kimi-gating-design.md §2 (authoritative). Binding refinements:
decisions.md.

Invariants (design §2.1/§2.3, hard rules):
  - Pure stdlib. No network, no clock, no randomness, no filesystem probes.
  - Same input -> same classification, byte for byte (deterministic).
  - Never raises. Unknown / missing pieces degrade to the safest LOUD context
    (binary / code-line / prose), never toward silent demotion.
  - No absolute-path input. Classification uses rel_path exactly as the
    scanner receives it (teeth tests pass bare basenames; pytest tmp paths
    must never leak in and false-trip ``test`` segments).
  - One-directional import: imports forensics_core only (for the existing
    _DOC_EXTS / _DOC_BASENAMES / _DOC_PATH_SEGMENTS / _is_agent_instruction_file
    / _COMMENT_PREFIXES / _LOG_CALL_RE / _QUOTE_CHARS tables). forensics_core
    never imports this module -> no circular dependency.

The classifier owns SIGNALS only. Consumers own POLICY (gate_evidence applies
a named policy table; v2.13.1 ships the ``yara`` policy, v2.13.2 will add
memory-heist / runtime-dynamism policies reusing this same module).

Created by Alex Greenshpun. License: PolyForm-Noncommercial-1.0.0.
"""

import os
import re

# One-directional import: reuse the existing signal tables / helpers so the
# classifier and the central inferer agree on what counts as a doc file, an
# agent-instruction file, a comment prefix, etc. (mirrors the
# scan_skill_threats reuse documented at forensics_core.py:611-620).
import forensics_core as core

# ---------------------------------------------------------------------------
# Tables (design §2.2). The doc/agent-instruction/comment tables are reused
# from forensics_core; the code/config/test/blocklist tables are new.
# ---------------------------------------------------------------------------

# Code extensions: the union consumers already use (scan_skill_threats
# code_exts) plus the YARA payload families (.ps1/.psm1/.bat/.cmd/.vbs/.hta/
# .jsp/.jspx/.asp/.aspx/.pl/.lua/.psgi/.cgi).
_CODE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".sh", ".bash", ".zsh",
    ".go", ".rs", ".php", ".java", ".swift", ".kt",
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".hta",
    ".jsp", ".jspx", ".asp", ".aspx",
    ".pl", ".lua", ".psgi", ".cgi",
}

# Operational data extensions. A live miner config is .json (batch-B
# real-config.json); must NOT be demoted by default -> config maps to direct
# under the YARA policy.
_CONFIG_EXTS = {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".xml",
    ".csv", ".env", ".properties", ".lock",
}

# Test-fixture path segments (EXACT segment equality, not substring — the
# _AUTHORITY_FP_PATH_RE substring sloppiness that hit latest/ and protest/
# is explicitly not repeated; design §2.2).
_TEST_PATH_SEGMENTS = {
    "test", "tests", "testing", "__tests__", "testdata", "test-data",
    "fixtures", "fixture", "mocks", "mock", "spec", "specs", "golden",
}

# Test-fixture basename patterns (anchored on the basename, design §2.2).
_TEST_BASENAME_RES = (
    re.compile(r"^test_[^/]*\.py$"),
    re.compile(r"[^/]*_test\.(py|go|rb|java|kt|rs)$"),
    re.compile(r"[^/]*\.(test|spec)\.(js|jsx|ts|tsx|mjs|cjs)$"),
    re.compile(r"^conftest\.py$"),
)

# Blocklist filename/path tokens (hyphen/underscore/dot delimited, design §2.2).
_BLOCKLIST_TOKENS = (
    "blocklist", "blacklist", "denylist", "filterlist", "easylist",
    "adblock", "ublock", "nocoin", "coinblocker",
)
_BLOCKLIST_TOKEN_RE = re.compile(
    r"(?:^|[-_.])(" + "|".join(_BLOCKLIST_TOKENS) + r")(?:[-_.]|$)")
_BLOCKLIST_PATH_SEGMENTS = {
    "blocklists", "blacklists", "denylists", "filters", "filter-lists",
}

# Security/privacy doc basenames (a deliberate SUBSET of _DOC_BASENAMES;
# readme is NOT included — README is prime attack real estate, design §2.2).
_SECURITY_DOC_STEMS = {"security", "privacy"}

# Shebang interpreters that upgrade a no-extension/unknown-ext file from
# binary to code (extensionless hook scripts / dropped stagers, design §2.2).
_SHEBANG_INTERPRETERS = (
    "sh", "bash", "zsh", "python", "python2", "python3",
    "perl", "ruby", "php", "node", "pwsh", "powershell",
)
_SHEBANG_RE = re.compile(r"^#!\s*(?:/usr/bin/env\s+)?(\S+)")

# Adblock-style filter rule line: ||example.com^ or ! comment or @@exception.
# Very specific to filter-list payloads; JSON/CSV config arrays do not match,
# so this content shape can fire alone without a config.json FP risk.
_FILTER_RULE_RE = re.compile(r"^\s*(?:\|\||@@|!|/|[a-z0-9-]+\s*$)", re.IGNORECASE)
_FILTER_RULE_DOMINANT_RE = re.compile(r"^\s*\|\|[^/\s]+\^")

# Content bound for the optional shebang / blocklist content signals (mirrors
# scan_yara._LINE_RESOLVE_MAX_BYTES so a >1MB or binary file is never probed
# twice just to classify it; design §2.2).
_CONTENT_MAX_BYTES = 1024 * 1024


# ---------------------------------------------------------------------------
# FileContext
# ---------------------------------------------------------------------------

class FileContext:
    """Immutable-ish context record for a carrier file's rel_path.

    Fields (design §2.1):
      primary:          "code" | "binary" | "config" | "prose-doc"
                        | "agent-instruction"
      is_test_fixture:  bool  (path-segment + anchored filename signals)
      is_blocklist:     bool  (filename/path markers + optional content shape)
      is_security_doc:  bool  (basename stem in {security, privacy})
    """

    __slots__ = ("primary", "is_test_fixture", "is_blocklist", "is_security_doc")

    def __init__(self, primary="binary", is_test_fixture=False,
                 is_blocklist=False, is_security_doc=False):
        self.primary = primary
        self.is_test_fixture = bool(is_test_fixture)
        self.is_blocklist = bool(is_blocklist)
        self.is_security_doc = bool(is_security_doc)

    def __repr__(self):
        return ("FileContext(primary={!r}, is_test_fixture={!r}, "
                "is_blocklist={!r}, is_security_doc={!r})".format(
                    self.primary, self.is_test_fixture,
                    self.is_blocklist, self.is_security_doc))

    def __eq__(self, other):
        if not isinstance(other, FileContext):
            return NotImplemented
        return (self.primary == other.primary
                and self.is_test_fixture == other.is_test_fixture
                and self.is_blocklist == other.is_blocklist
                and self.is_security_doc == other.is_security_doc)

    def __hash__(self):
        return hash((self.primary, self.is_test_fixture,
                     self.is_blocklist, self.is_security_doc))


# ---------------------------------------------------------------------------
# Path normalization (design §2.2: replace \\ with /, lower, split on /).
# Never touches the filesystem. rel_path is used exactly as received.
# ---------------------------------------------------------------------------

def _normalize_parts(rel_path):
    """Return (lowered_parts, lowered_full) for a rel_path. Empty -> ([], "").

    ``..`` and ``.`` segments are collapsed (FIX 3 / DEFECT-2) so a demoting
    segment the path has escaped (``tests/../shell.php``, ``docs/../shell.php``,
    ``denylists/../evil.php``) cannot fire ``is_test_fixture`` / ``is_blocklist``
    / ``prose-doc`` segment membership. The lowered full string is kept verbatim
    (still used for basename extraction); only the segment list is collapsed.
    """
    if not rel_path:
        return [], ""
    norm = rel_path.replace("\\", "/").lower()
    raw = [p for p in norm.split("/") if p]
    parts = []
    for p in raw:
        if p == ".":
            continue
        if p == "..":
            if parts:
                parts.pop()
            # A leading ``..`` that escapes root has nothing to pop: drop it so
            # it cannot carry a demoting segment into the membership checks.
            continue
        parts.append(p)
    return parts, norm


def _basename_stem(rel_path):
    """Lowercased basename stem (no ext). '' for empty input."""
    if not rel_path:
        return ""
    base = os.path.basename(rel_path.replace("\\", "/"))
    return os.path.splitext(base)[0].lower()


def _ext(rel_path):
    """Lowercased extension incl. leading dot. '' for empty input."""
    if not rel_path:
        return ""
    return os.path.splitext(rel_path)[1].lower()


def _decode_content(content):
    """Return a str for bytes/str content <= _CONTENT_MAX_BYTES, else None.

    Bytes are decoded UTF-8 (errors='replace'); >1MB or undecodable -> None.
    Never raises."""
    if content is None:
        return None
    if isinstance(content, str):
        if len(content) > _CONTENT_MAX_BYTES:
            return None
        return content
    if isinstance(content, (bytes, bytearray)):
        if len(content) > _CONTENT_MAX_BYTES:
            return None
        try:
            return bytes(content).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return None
    return None


# ---------------------------------------------------------------------------
# classify_file_context
# ---------------------------------------------------------------------------

def _is_doc_carrier(ext, stem, parts):
    """Doc-carrier signal, gated by extension (FIX 1, design §2.2 refined).

    The doc-EXTENSION branch (``.md``/``.txt`` cheatsheets) always demotes: a
    doc extension can never be executed as a webshell by a web server. The
    doc-BASENAME (``readme``, ``license``, ``changelog``, ...) and doc-PATH-
    SEGMENT (``docs/``, ``documentation/``) branches demote ONLY when the
    extension is a doc extension OR empty/unknown — NEVER on a code extension.
    A live payload on an executable extension (``readme.php``, ``license.bat``,
    ``docs/shell.php``) is code, not prose, regardless of its basename stem or
    the directory it sits in. Config extensions are operational data, not prose,
    so they are not demoted by the basename/path branches either.
    """
    if ext in core._DOC_EXTS:
        return True
    if ext in _CODE_EXTS or ext in _CONFIG_EXTS:
        return False
    # empty / unknown extension: basename + path-segment branches apply.
    if stem in core._DOC_BASENAMES:
        return True
    return any(seg in core._DOC_PATH_SEGMENTS for seg in parts)


def _shebang_is_code(text):
    """True if line 1 is a #! shebang for a known interpreter. Never raises."""
    if not text:
        return False
    first = text.split("\n", 1)[0]
    m = _SHEBANG_RE.match(first)
    if not m:
        return False
    interp = m.group(1).lower()
    # Strip a leading path component: /usr/bin/python -> python.
    interp_base = os.path.basename(interp)
    return interp_base in _SHEBANG_INTERPRETERS or interp in _SHEBANG_INTERPRETERS


def _content_is_blocklist(text):
    """Optional content signal (design §2.2). True when >=70% of non-empty
    lines are adblock-style ||domain^ filter rules. This shape is specific to
    filter-list payloads (JSON/CSV config arrays do not match), so it may fire
    alone without a config FP risk. Quoted-string-array shape is intentionally
    NOT used as a standalone trigger (would FP on real .json configs)."""
    if not text:
        return False
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return False
    hits = sum(1 for ln in lines if _FILTER_RULE_DOMINANT_RE.match(ln))
    return hits / len(lines) >= 0.70


def classify_file_context(rel_path, content=None):
    """Classify a carrier file's rel_path into a FileContext.

    ``content`` (str or bytes, optional, <=1MB) enables two optional signals:
    the shebang upgrade (no-ext file -> code) and the blocklist content shape.
    Both are no-ops for the YARA policy (binary/code both map to direct); they
    exist for the v2.13.2 memory-heist / runtime-dynamism consumers and future
    scanners. Never probes the filesystem — content comes from the caller's
    already-open read. Never raises; unknown pieces degrade to LOUD context.
    """
    try:
        parts, norm = _normalize_parts(rel_path)
        # Normalize backslashes to forward slashes BEFORE the core helpers so
        # os.path.basename splits Windows paths correctly on POSIX (design §2.2
        # normalizes first; the core helpers rely on os.path.basename which is
        # platform-dependent for "\\").
        norm_path = rel_path.replace("\\", "/") if rel_path else rel_path
        ext = _ext(norm_path)
        stem = _basename_stem(norm_path)

        # --- primary (precedence: agent-instruction > prose-doc > code >
        # config > binary; design §2.2) ---
        primary = "binary"
        if core._is_agent_instruction_file(norm_path):
            primary = "agent-instruction"
        elif _is_doc_carrier(ext, stem, parts):
            primary = "prose-doc"
        elif ext in _CODE_EXTS:
            primary = "code"
        elif ext in _CONFIG_EXTS:
            primary = "config"
        else:
            primary = "binary"
            # Shebang upgrade: a no-extension / unknown-ext file whose first
            # line is a known-interpreter shebang is a script, not a blob.
            text = _decode_content(content)
            if text and _shebang_is_code(text):
                primary = "code"

        # --- is_test_fixture (path segment OR anchored basename) ---
        is_test_fixture = (
            any(seg in _TEST_PATH_SEGMENTS for seg in parts)
            or any(rx.match(os.path.basename(norm)) for rx in _TEST_BASENAME_RES)
        )

        # --- is_blocklist (filename token OR path segment OR content shape) ---
        # FIX 1: the basename-token signal is restricted to non-code extensions
        # (config/prose/binary) — a .bat named blacklist.bat or a .php named
        # denylist.php is a runnable dropper / live webshell, not a filter list.
        # The path-segment + content-shape signals stay for real filter-list
        # files (denylists/rules.txt, adblock-style content).
        is_blocklist = (
            (ext not in _CODE_EXTS and bool(_BLOCKLIST_TOKEN_RE.search(stem)))
            or any(seg in _BLOCKLIST_PATH_SEGMENTS for seg in parts)
        )
        if not is_blocklist:
            text = _decode_content(content) if content is not None else None
            if text and _content_is_blocklist(text):
                is_blocklist = True

        # --- is_security_doc (basename stem in {security, privacy}) ---
        is_security_doc = stem in _SECURITY_DOC_STEMS

        return FileContext(
            primary=primary,
            is_test_fixture=is_test_fixture,
            is_blocklist=is_blocklist,
            is_security_doc=is_security_doc,
        )
    except Exception:
        # Never raise. Degrade to the safest LOUD context: binary (YARA ->
        # direct -> manifest severity) with no demoting flags.
        return FileContext(primary="binary")


# ---------------------------------------------------------------------------
# classify_line_context (design §2.2)
# ---------------------------------------------------------------------------

def _fenced_spans(text):
    """Return [(open, close), ...] 1-based line pairs for CLOSED ``` fences.

    Fences are lines whose left-stripped content starts with ``` (handles
    indented fences and language tags like ```python). Pairs are formed
    sequentially; a trailing unpaired fence yields NO span, so the unclosed
    tail is NOT treated as fenced (fail-safe toward prose, design §2.2)."""
    fences = []
    for i, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            fences.append(i)
    spans = []
    for j in range(0, len(fences) - 1, 2):
        spans.append((fences[j], fences[j + 1]))
    return spans


def _line_is_comment_or_string(line):
    """True if a raw code/config line is a comment, a quoted string literal,
    or a log/print call (reuses the forensics_core tables applied to the raw
    line, not the scanner's snippet; design §2.2). Never raises."""
    if not line:
        return False
    snip = line.lstrip()
    if snip.startswith(core._COMMENT_PREFIXES):
        return True
    if snip.startswith(core._QUOTE_CHARS):
        return True
    if core._LOG_CALL_RE.search(snip):
        return True
    return False


def classify_line_context(rel_path, content, line_no):
    """Classify a 1-based line within a file's content.

    Returns one of: "code-line" | "comment-or-string" | "prose" | "fenced-code".

    - prose-primary / agent-instruction file -> markdown ``` fence tracking up
      to line_no. Inside a CLOSED fence -> "fenced-code"; else "prose". An
      unclosed fence fails toward "prose" (the loud direction for directive
      scanners), NEVER toward demotion (design §2.2, pinned by test).
    - code-primary / config file -> the raw line: comment-prefix / quote /
      log-call -> "comment-or-string"; else "code-line".
    - binary file -> "code-line" (loud default; line context is not meaningful
      for binaries and YARA does not consume line_ctx).
    Never raises."""
    try:
        if line_no is None:
            line_no = 0
        line_no = int(line_no)
        if line_no < 1:
            # No usable line: loud defaults per primary.
            fctx = classify_file_context(rel_path)
            if fctx.primary in ("prose-doc", "agent-instruction"):
                return "prose"
            return "code-line"

        text = content if isinstance(content, str) else _decode_content(content)
        if text is None:
            # Undecodable / missing content: loud default per primary.
            fctx = classify_file_context(rel_path)
            if fctx.primary in ("prose-doc", "agent-instruction"):
                return "prose"
            return "code-line"

        fctx = classify_file_context(rel_path)

        if fctx.primary in ("prose-doc", "agent-instruction"):
            spans = _fenced_spans(text)
            for open_l, close_l in spans:
                if open_l < line_no < close_l:
                    return "fenced-code"
            return "prose"

        if fctx.primary in ("code", "config"):
            lines = text.splitlines()
            if 1 <= line_no <= len(lines):
                return "comment-or-string" if _line_is_comment_or_string(
                    lines[line_no - 1]) else "code-line"
            return "code-line"

        # binary or unknown -> loud default.
        return "code-line"
    except Exception:
        # Never raise. Loud default: prose for prose-primary, else code-line.
        try:
            fctx = classify_file_context(rel_path)
            if fctx.primary in ("prose-doc", "agent-instruction"):
                return "prose"
        except Exception:
            pass
        return "code-line"


# ---------------------------------------------------------------------------
# gate_evidence (design §2.1, §3.1, §5.3). Consumers own policy; the module
# holds the named policy tables. v2.13.1 ships "yara".
# ---------------------------------------------------------------------------

def _yara_policy(file_ctx, line_ctx):
    """YARA file-context policy (design §3.1).

    Flags win over primary (a .php under tests/ -> inferred). code/binary/
    config with no flags -> direct (live payload / live miner config stay at
    manifest severity). agent-instruction / prose-doc / test-fixture /
    blocklist -> inferred (YARA matches code artifacts, not prose directives;
    a webshell's bytes inside SKILL.md are inert until extracted+executed)."""
    if file_ctx.is_test_fixture or file_ctx.is_blocklist:
        return "inferred"
    if file_ctx.primary in ("prose-doc", "agent-instruction"):
        return "inferred"
    # code / binary / config (and any unknown primary) -> direct.
    return "direct"


_POLICIES = {
    "yara": _yara_policy,
}


def gate_evidence(file_ctx, line_ctx=None, *, policy):
    """Apply a named per-consumer policy to a (file_ctx, line_ctx) pair and
    return "direct" or "inferred".

    ``policy`` is a policy name string (v2.13.1: "yara"). Unknown policy names
    degrade to "direct" (the loud direction) rather than raising. Never
    suppresses a finding — the caller sets evidence_class and the report layer
    caps + records original_severity (fail-loud invariant)."""
    try:
        fn = _POLICIES.get(policy)
        if fn is None:
            return "direct"
        return fn(file_ctx, line_ctx)
    except Exception:
        return "direct"
