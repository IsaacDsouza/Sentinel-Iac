from typer.testing import CliRunner

from sentinel.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "sentinel-iac" in result.stdout


def test_scan_defaults(tmp_path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "SARIF results written to" in result.stdout


def test_scan_nonexistent_path() -> None:
    result = runner.invoke(app, ["scan", "C:\\nonexistent-path-12345"])
    assert result.exit_code == 1
    assert "Error" in result.stdout


def test_fix_needs_api_key(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "")
    result = runner.invoke(app, ["fix"])
    assert result.exit_code == 1
    assert "OPENAI_API_KEY" in result.stdout
