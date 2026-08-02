"""Tests for scan_binary.py - Binary Camouflage Scanner."""

import os
import struct
import scan_binary as scanner


def _make_valid_pe_bytes():
    """Build a minimal but structurally valid MZ+PE stub (no actual code)."""
    # DOS header: MZ magic + e_lfanew at offset 0x3C pointing to offset 0x40
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 0x3C, 0x40)  # e_lfanew = 0x40

    # PE signature at offset 0x40
    pe_sig = b'PE\x00\x00'

    # Pad to make a recognizable blob
    padding = bytes(32)
    return bytes(dos_header) + pe_sig + padding


class TestEmbeddedPe:
    def test_png_with_embedded_pe_is_critical(self, tmp_path):
        """PNG file with a valid PE at a non-zero offset should trigger a CRITICAL finding."""
        png_header = bytes([
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,  # PNG magic
            0x00, 0x00, 0x00, 0x0d,                              # IHDR length
            0x49, 0x48, 0x44, 0x52,                              # IHDR type
        ])
        # Pad PNG area then embed PE at offset 256
        filler = bytes(256 - len(png_header))
        pe_blob = _make_valid_pe_bytes()
        content = png_header + filler + pe_blob

        evil_png = tmp_path / "image.png"
        evil_png.write_bytes(content)

        findings = scanner.scan_embedded_pe(str(evil_png), "image.png")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) >= 1, f"Expected CRITICAL embedded PE finding, got: {[f.title for f in findings]}"
        assert any("embedded pe" in f.title.lower() for f in critical)
        assert any(f.category == "embedded-executable" for f in critical)

    def test_normal_png_no_finding(self, tmp_path):
        """A clean PNG file without any PE content should produce no findings."""
        png_header = bytes([
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
            0x00, 0x00, 0x00, 0x0d,
            0x49, 0x48, 0x44, 0x52,
        ])
        content = png_header + bytes(512)

        clean_png = tmp_path / "clean.png"
        clean_png.write_bytes(content)

        findings = scanner.scan_embedded_pe(str(clean_png), "clean.png")
        assert len(findings) == 0, f"Expected no findings for clean PNG, got: {[f.title for f in findings]}"

    def test_exe_is_skipped(self, tmp_path):
        """A normal .exe file (MZ at offset 0) should not trigger embedded PE detection."""
        pe_blob = _make_valid_pe_bytes()
        exe_file = tmp_path / "normal.exe"
        exe_file.write_bytes(pe_blob)

        findings = scanner.scan_embedded_pe(str(exe_file), "normal.exe")
        assert len(findings) == 0, f"Expected no findings for .exe, got: {[f.title for f in findings]}"

    def test_dll_is_skipped(self, tmp_path):
        """A .dll file should be skipped regardless of content."""
        pe_blob = _make_valid_pe_bytes()
        dll_file = tmp_path / "lib.dll"
        dll_file.write_bytes(pe_blob)

        findings = scanner.scan_embedded_pe(str(dll_file), "lib.dll")
        assert len(findings) == 0, f"Expected no findings for .dll, got: {[f.title for f in findings]}"

    def test_pdf_with_embedded_pe_is_critical(self, tmp_path):
        """A PDF containing an embedded PE should also be detected."""
        pdf_header = b'%PDF-1.4\n'
        filler = bytes(128)
        pe_blob = _make_valid_pe_bytes()
        content = pdf_header + filler + pe_blob

        evil_pdf = tmp_path / "document.pdf"
        evil_pdf.write_bytes(content)

        findings = scanner.scan_embedded_pe(str(evil_pdf), "document.pdf")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) >= 1, f"Expected CRITICAL finding in PDF, got: {[f.title for f in findings]}"

    def test_mz_without_valid_pe_sig_no_finding(self, tmp_path):
        """MZ bytes without a valid PE signature should not trigger a finding."""
        # MZ at offset 64 but e_lfanew points to garbage (no PE\x00\x00)
        content = bytes(64) + b'MZ' + bytes(256)
        fake_bin = tmp_path / "fake.bin"
        fake_bin.write_bytes(content)

        findings = scanner.scan_embedded_pe(str(fake_bin), "fake.bin")
        assert len(findings) == 0, f"Expected no finding for MZ-only (no PE sig), got: {[f.title for f in findings]}"

    def test_tiny_file_skipped(self, tmp_path):
        """Files under 64 bytes should be skipped entirely."""
        tiny = tmp_path / "tiny.png"
        tiny.write_bytes(b'MZ' + bytes(30))

        findings = scanner.scan_embedded_pe(str(tiny), "tiny.png")
        assert len(findings) == 0, "Expected no findings for tiny file"


class TestScanBinaryMain:
    """Regression tests for Issue #38: the `os.access(filepath, os.X_OK)` branch
    on a data file (no exec magic, no shebang) must emit a LOW
    permission-hygiene finding, NOT HIGH binary-camouflage. Magic mismatch /
    embedded-PE upstream branches stay CRITICAL (no regression)."""

    def _run_main(self, args, monkeypatch):
        """Invoke scanner.main() with the given argv and capture emitted JSON.
        Returns the parsed JSON dict (findings live at `--format json` output)."""
        import sys as _sys
        import io
        import json as _json
        from contextlib import redirect_stdout
        buf = io.StringIO()
        monkeypatch.setattr(_sys, "argv", ["scan_binary.py", *args, "--format", "json"])
        with redirect_stdout(buf):
            scanner.main()
        out = buf.getvalue().strip()
        # scanner emits a status line "[*] Scanning ..." BEFORE the JSON;
        # strip that prefix so json.loads succeeds.
        if out.startswith("["):
            return _json.loads(out)
        return _json.loads(out.split("\n", 1)[1])

    def test_exec_bit_on_json_is_low_permission_hygiene(self, tmp_path, monkeypatch):
        """A .json file with +x but no exec magic must surface a LOW finding
        under category=permission-hygiene. Issue #38: a HIGH/binary-camouflage
        was amplifying false positives on every data file with the bit set."""
        if os.name != 'posix':
            return  # chmod semantics differ on Windows; regression is POSIX-only.
        data = tmp_path / "data.json"
        data.write_bytes(b'{"hello": "world"}\n')
        os.chmod(data, 0o755)
        findings = self._run_main([str(tmp_path)], monkeypatch)
        exec_findings = [f for f in findings
                         if "Executable" in f["title"] or "executable" in f["title"].lower()
                         or "permission" in f["category"].lower()]
        assert exec_findings, f"expected at least one finding for chmod +x data file: {findings}"
        # No HIGH binary-camouflage for data file with only exec bit + no magic.
        high_camo = [f for f in exec_findings
                     if f["severity"] == "high" and f["category"] == "binary-camouflage"]
        assert high_camo == [], (
            "Issue #38: chmod +x on a data file (no exec magic, no shebang) "
            "must NOT be HIGH/binary-camouflage. Got: "
            f"{[(f['title'], f['severity'], f['category']) for f in high_camo]}"
        )
        # The LOW permission-hygiene finding is still emitted (we want the
        # signal, just at the right severity).
        low_hygiene = [f for f in exec_findings
                       if f["severity"] == "low" and f["category"] == "permission-hygiene"]
        assert low_hygiene, (
            "expected a LOW permission-hygiene finding for chmod +x data file, "
            f"got: {[(f['title'], f['severity'], f['category']) for f in exec_findings]}"
        )

    def test_exec_bit_on_markdown_is_low_permission_hygiene(self, tmp_path, monkeypatch):
        """Same expectation for .md files."""
        if os.name != 'posix':
            return
        readme = tmp_path / "README.md"
        readme.write_bytes(b"# Title\n")
        os.chmod(readme, 0o755)
        findings = self._run_main([str(tmp_path)], monkeypatch)
        # Only findings that pertain to this file
        per_file = [f for f in findings if f["file"].endswith("README.md")]
        assert per_file, f"expected at least one finding for README.md: {findings}"
        high_camo = [f for f in per_file
                     if f["severity"] == "high" and f["category"] == "binary-camouflage"]
        assert high_camo == [], (
            "Issue #38: chmod +x on .md must NOT be HIGH/binary-camouflage. "
            f"Got: {[(f['title'], f['severity'], f['category']) for f in high_camo]}"
        )

    def test_exec_bit_on_png_is_low_permission_hygiene(self, tmp_path, monkeypatch):
        """Same expectation for .png files. (PNG content is unrelated; what
        matters is no exec magic and no shebang, both already skipped above.)"""
        if os.name != 'posix':
            return
        # A real (non-PE) PNG so the magic-mismatch and embedded-PE branches
        # don't trip on it. Valid 1x1 PNG: \x89PNG\r\n\x1a\n + IHDR chunk.
        png = tmp_path / "img.png"
        png.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\x0dIHDR"
            b"\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x02\x00\x00\x00\x90wS\xde"
            b"\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x00\x03\x00\x01"
            b"\x9b\x9c\xd8\xa9"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        os.chmod(png, 0o755)
        findings = self._run_main([str(tmp_path)], monkeypatch)
        per_file = [f for f in findings if f["file"].endswith("img.png")]
        high_camo = [f for f in per_file
                     if f["severity"] == "high" and f["category"] == "binary-camouflage"]
        assert high_camo == [], (
            "Issue #38: chmod +x on a clean PNG must NOT be "
            f"HIGH/binary-camouflage. Got: {[(f['title'], f['severity'], f['category']) for f in high_camo]}"
        )

    def test_embedded_pe_remains_critical(self, tmp_path):
        """No regression: a PNG with an embedded valid PE must still produce a
        CRITICAL embedded-executable finding (this branch is upstream of the
        chmod +x demote and was explicitly excluded from the Issue #38 fix)."""
        png_header = bytes([
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
            0x00, 0x00, 0x00, 0x0d,
            0x49, 0x48, 0x44, 0x52,
        ])
        filler = bytes(256 - len(png_header))
        pe_blob = _make_valid_pe_bytes()
        png = tmp_path / "evil.png"
        png.write_bytes(png_header + filler + pe_blob)
        findings = scanner.scan_embedded_pe(str(png), "evil.png")
        crit = [f for f in findings if f.severity == "critical"
                and f.category == "embedded-executable"]
        assert crit, f"embedded-PE branch must remain CRITICAL, got: {findings}"

    def test_magic_mismatch_remains_critical(self, tmp_path, monkeypatch):
        """No regression: a .png with ELF magic (a real camouflaged binary) must
        still produce a CRITICAL binary-camouflage finding. This branch is
        upstream of the chmod +x demote and was explicitly excluded from the
        Issue #38 fix."""
        png = tmp_path / "trojan.png"
        png.write_bytes(b"\x7fELF" + b"\x00" * 200)  # ELF magic, .png extension
        findings = self._run_main([str(tmp_path)], monkeypatch)
        crit_camo = [f for f in findings
                     if f["file"].endswith("trojan.png")
                     and f["severity"] == "critical"
                     and f["category"] == "binary-camouflage"]
        assert crit_camo, (
            "magic-mismatch branch must remain CRITICAL/binary-camouflage; "
            f"got: {findings}"
        )
