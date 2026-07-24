from pathlib import Path
from types import SimpleNamespace

from aegis import dependencies
from aegis.security.security_memory import (
    SecurityMemoryService,
)
from aegis.security.sqlite_memory import (
    SQLiteProjectMemoryStore,
)


def test_security_memory_dependency_is_lazy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database_path = (
        tmp_path
        / "data"
        / "security-memory.sqlite3"
    )

    monkeypatch.setattr(
        dependencies,
        "get_settings",
        lambda: SimpleNamespace(
            security_memory_database_path=(
                database_path
            )
        ),
    )

    dependencies.get_security_memory_service.cache_clear()

    assert database_path.exists() is False
    assert database_path.parent.exists() is False

    service = (
        dependencies
        .get_security_memory_service()
    )

    assert isinstance(
        service,
        SecurityMemoryService,
    )
    assert isinstance(
        service.store,
        SQLiteProjectMemoryStore,
    )
    assert service.store.database_path == (
        database_path
    )
    assert database_path.is_file()


def test_security_memory_dependency_is_cached(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database_path = (
        tmp_path
        / "security-memory.sqlite3"
    )

    monkeypatch.setattr(
        dependencies,
        "get_settings",
        lambda: SimpleNamespace(
            security_memory_database_path=(
                database_path
            )
        ),
    )

    dependencies.get_security_memory_service.cache_clear()

    first = (
        dependencies
        .get_security_memory_service()
    )
    second = (
        dependencies
        .get_security_memory_service()
    )

    assert first is second


def test_default_memory_path_respects_xdg_data_home(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from aegis.config.settings import (
        _default_security_memory_database_path,
    )

    monkeypatch.setenv(
        "XDG_DATA_HOME",
        str(tmp_path),
    )

    assert (
        _default_security_memory_database_path()
        == (
            tmp_path
            / "aegis"
            / "security-memory.sqlite3"
        )
    )
