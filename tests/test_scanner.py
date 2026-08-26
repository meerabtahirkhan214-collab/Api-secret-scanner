import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import scan_file, mask_secret


def test_mask_secret_normal_length():
    result = mask_secret("AKIAABCDEFGHIJKLMNOP")
    assert result.startswith("AKIA")
    assert result.endswith("NOP")
    assert "*" in result


def test_mask_secret_short_string():
    result = mask_secret("short")
    assert result == "*****"


def test_detects_aws_key(tmp_path):
    f = tmp_path / "leak.py"
    f.write_text('aws_key = "AKIAABCDEFGHIJKLMNOP"')
    findings = scan_file(str(f))
    assert len(findings) == 1
    assert findings[0][1] == "AWS Access Key"


def test_detects_google_key(tmp_path):
    f = tmp_path / "leak.py"
    f.write_text('google_key = "AIzaSyD1234567890abcdefghijklmnopqr"')
    findings = scan_file(str(f))
    assert any(f[1] == "Google API Key" for f in findings)


def test_detects_github_token(tmp_path):
    f = tmp_path / "leak.py"
    f.write_text('github_token = "ghp_1234567890abcdefghijklmnopqrstuvwx"')
    findings = scan_file(str(f))
    assert any(f[1] == "GitHub Token" or f[1] == "Generic Secret" for f in findings)


def test_clean_file_no_findings(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text('print("hello world")\nx = 5\n')
    findings = scan_file(str(f))
    assert findings == []


def test_nonexistent_file_returns_empty():
    findings = scan_file("this_file_does_not_exist.py")
    assert findings == []