from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from aegis.schemas.repository_policy import (
    RepositoryPolicyConfig,
)


DEFAULT_POLICY_FILENAMES = (
    ".aegis.yml",
    ".aegis.yaml",
)


class RepositoryPolicyError(ValueError):
    pass


def discover_repository_policy(
    repository_root: str | Path,
) -> Path | None:
    root = Path(
        repository_root
    ).expanduser().resolve()

    discovered = [
        root / filename
        for filename in DEFAULT_POLICY_FILENAMES
        if (root / filename).is_file()
    ]

    if len(discovered) > 1:
        raise RepositoryPolicyError(
            "Repository contains both .aegis.yml and "
            ".aegis.yaml; keep only one policy file."
        )

    return (
        discovered[0]
        if discovered
        else None
    )


def load_repository_policy(
    path: str | Path,
) -> RepositoryPolicyConfig:
    policy_path = Path(
        path
    ).expanduser()

    if not policy_path.exists():
        raise RepositoryPolicyError(
            "Repository policy file does not exist."
        )

    if not policy_path.is_file():
        raise RepositoryPolicyError(
            "Repository policy path is not a file."
        )

    try:
        raw_text = policy_path.read_text(
            encoding="utf-8",
        )
    except OSError as exc:
        raise RepositoryPolicyError(
            "Repository policy file could not be read."
        ) from exc

    try:
        payload = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise RepositoryPolicyError(
            "Repository policy YAML is invalid."
        ) from exc

    if payload is None:
        raise RepositoryPolicyError(
            "Repository policy file is empty."
        )

    if not isinstance(payload, dict):
        raise RepositoryPolicyError(
            "Repository policy root must be a mapping."
        )

    try:
        return RepositoryPolicyConfig.model_validate(
            payload
        )
    except ValidationError as exc:
        raise RepositoryPolicyError(
            "Repository policy validation failed: "
            f"{exc}"
        ) from exc


def load_discovered_repository_policy(
    repository_root: str | Path,
) -> tuple[
    Path | None,
    RepositoryPolicyConfig | None,
]:
    path = discover_repository_policy(
        repository_root
    )

    if path is None:
        return None, None

    return path, load_repository_policy(path)
