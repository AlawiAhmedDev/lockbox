import io
import json

import pytest

from lockbox.cli import main

PW = "correct horse battery staple"
FAST = ["--kdf-time", "1", "--kdf-memory-mib", "1", "--kdf-parallelism", "1"]


def run(monkeypatch, capsys, vault, *args, stdin=PW):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin + "\n"))
    code = main(["--vault", str(vault), "--password-stdin", *args])
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture()
def vpath(tmp_path, monkeypatch, capsys):
    path = tmp_path / "v.json"
    code, _, _ = run(monkeypatch, capsys, path, "init", *FAST)
    assert code == 0
    return path


def test_full_workflow(vpath, monkeypatch, capsys):
    assert run(monkeypatch, capsys, vpath, "add", "github", "--username", "me",
               "--generate", "--length", "24")[0] == 0
    assert run(monkeypatch, capsys, vpath, "add", "bank", stdin=f"{PW}\nazerty123")[0] == 0

    code, out, _ = run(monkeypatch, capsys, vpath, "get", "github")
    assert code == 0 and len(out.strip()) == 24

    code, out, _ = run(monkeypatch, capsys, vpath, "list", "--json")
    names = [e["name"] for e in json.loads(out)]
    assert names == ["bank", "github"] and "password" not in out

    code, out, _ = run(monkeypatch, capsys, vpath, "audit", "--fail")
    assert code == 2 and "bank" in out and "very common password" in out

    assert run(monkeypatch, capsys, vpath, "edit", "bank", "--generate")[0] == 0
    code, out, _ = run(monkeypatch, capsys, vpath, "audit", "--fail")
    assert code == 0 and "healthy" in out

    assert run(monkeypatch, capsys, vpath, "rm", "bank", "--yes")[0] == 0
    code, _, err = run(monkeypatch, capsys, vpath, "get", "bank")
    assert code == 1 and "no entry" in err


def test_wrong_password_exit_code(vpath, monkeypatch, capsys):
    code, _, err = run(monkeypatch, capsys, vpath, "list", stdin="nope")
    assert code == 3 and "wrong master password" in err


def test_passwd(vpath, monkeypatch, capsys):
    assert run(monkeypatch, capsys, vpath, "passwd", "--rotate-key",
               stdin=f"{PW}\nnew master passphrase")[0] == 0
    assert run(monkeypatch, capsys, vpath, "list")[0] == 3
    assert run(monkeypatch, capsys, vpath, "list", stdin="new master passphrase")[0] == 0


def test_info_needs_no_password(vpath, monkeypatch, capsys):
    code, out, _ = run(monkeypatch, capsys, vpath, "info", stdin="")
    assert code == 0 and "argon2id" in out and "AES-256-GCM" in out


def test_generate(monkeypatch, capsys, tmp_path):
    code, out, err = run(monkeypatch, capsys, tmp_path / "none.json", "generate",
                         "--count", "3", "--length", "16", stdin="")
    assert code == 0 and len(out.split()) == 3 and "bits of entropy" in err
