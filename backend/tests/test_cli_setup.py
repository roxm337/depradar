import pytest
from sqlalchemy import delete

from depradar.domain.entities import Owner, OwnerSession
from depradar.domain.security import verify_password
from depradar.interfaces import cli

from .conftest import Harness


def test_setup_owner_uses_hidden_password_and_initializes_once(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with harness.factory.begin() as db:
        db.execute(delete(OwnerSession))
        db.execute(delete(Owner))
    monkeypatch.setattr(cli, "session_factory", lambda: harness.factory)
    monkeypatch.setattr("sys.argv", ["depradar", "setup-owner"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: "owner-private-password")
    cli.main()
    with harness.factory() as db:
        owner = db.get(Owner, 1)
        assert owner and verify_password("owner-private-password", owner.password_hash)
    output = capsys.readouterr()
    assert "Owner initialized" in output.out
    assert "owner-private-password" not in output.out
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2


def test_setup_owner_rejects_mismatched_confirmation(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "session_factory", lambda: harness.factory)
    monkeypatch.setattr("sys.argv", ["depradar", "setup-owner"])
    passwords = iter(["owner-private-password", "a-different-password"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(passwords))
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
