from pathlib import Path

from sentinel.remediate.agent import _apply_diff
from sentinel.remediate.tools import tool_read_file


def test_apply_diff_simple() -> None:
    original = 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'
    diff = """--- a/main.tf
+++ b/main.tf
@@ -1,3 +1,3 @@
 resource "aws_s3_bucket" "b" {
-  acl = "public-read"
+  acl = "private"
 }
"""
    result = _apply_diff(original, diff)
    assert result is not None
    assert '"private"' in result
    assert '"public-read"' not in result


def test_apply_diff_no_changes() -> None:
    original = 'resource "aws_s3_bucket" "b" {\n}\n'
    diff = "--- a/main.tf\n+++ b/main.tf\n"
    result = _apply_diff(original, diff)
    assert result == original


def test_apply_diff_add_line() -> None:
    original = 'resource "aws_s3_bucket" "b" {\n}\n'
    diff = """--- a/main.tf
+++ b/main.tf
@@ -1,2 +1,3 @@
 resource "aws_s3_bucket" "b" {
+  acl = "private"
 }
"""
    result = _apply_diff(original, diff)
    assert result is not None
    assert "private" in result


def test_tool_read_file_missing(tmp_path: Path) -> None:
    result = tool_read_file(tmp_path, "nonexistent.tf")
    assert "Error" in result


def test_tool_read_file_exists(tmp_path: Path) -> None:
    f = tmp_path / "test.tf"
    f.write_text('resource "aws_s3_bucket" "b" {}')
    result = tool_read_file(tmp_path, "test.tf")
    assert "aws_s3_bucket" in result
