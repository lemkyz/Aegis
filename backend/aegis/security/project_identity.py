from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from aegis.schemas.memory import RepositoryContext


class ProjectIdentityResolver:
    """
    Resolves durable project identity and source revision without
    executing commands through a shell.
    """

    name = "aegis-project-identity-resolver-v1"

    _maximum_untracked_file_bytes = 10 * 1024 * 1024
    _maximum_untracked_total_bytes = 50 * 1024 * 1024

    def resolve(
        self,
        path: str | Path,
    ) -> RepositoryContext:
        requested_path = Path(path).expanduser()

        if not requested_path.exists():
            raise ValueError(
                "Repository path does not exist."
            )

        resolved_path = requested_path.resolve()

        if resolved_path.is_file():
            resolved_path = resolved_path.parent

        repository_root = self._git_repository_root(
            resolved_path
        )

        if repository_root is None:
            return self._resolve_local_directory(
                resolved_path
            )

        remote = self._origin_remote(
            repository_root
        )
        canonical_remote = (
            self._canonicalize_remote(remote)
            if remote is not None
            else None
        )

        if canonical_remote:
            identity_source = "git_remote"
            identity_value = canonical_remote
        else:
            identity_source = "local_path"
            identity_value = self._normalized_path(
                repository_root
            )

        project_id = self._stable_id(
            "project",
            identity_source,
            identity_value,
        )

        head_commit = self._optional_git_text(
            repository_root,
            "rev-parse",
            "HEAD",
        )
        branch = self._optional_git_text(
            repository_root,
            "branch",
            "--show-current",
        ) or None

        status = self._git_bytes(
            repository_root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        )
        dirty = bool(status)

        revision = self._git_revision(
            repository_root=repository_root,
            head_commit=head_commit,
            dirty=dirty,
        )

        return RepositoryContext(
            project_id=project_id,
            repository_root=self._normalized_path(
                repository_root
            ),
            identity_source=identity_source,
            remote=canonical_remote,
            branch=branch,
            head_commit=head_commit,
            revision=revision,
            dirty=dirty,
        )

    def _git_revision(
        self,
        *,
        repository_root: Path,
        head_commit: str | None,
        dirty: bool,
    ) -> str:
        if head_commit is not None and not dirty:
            return f"git:{head_commit}"

        working_tree_digest = (
            self._working_tree_digest(
                repository_root
            )
        )

        if head_commit is not None:
            return (
                f"git:{head_commit}:"
                f"dirty:{working_tree_digest}"
            )

        return (
            "working-tree:"
            f"{working_tree_digest}"
        )

    def _working_tree_digest(
        self,
        repository_root: Path,
    ) -> str:
        digest = hashlib.sha256()

        self._update_digest_section(
            digest,
            b"unstaged-diff",
            self._git_bytes(
                repository_root,
                "diff",
                "--binary",
                "--no-ext-diff",
                "--",
            ),
        )

        self._update_digest_section(
            digest,
            b"staged-diff",
            self._git_bytes(
                repository_root,
                "diff",
                "--cached",
                "--binary",
                "--no-ext-diff",
                "--",
            ),
        )

        untracked_output = self._git_bytes(
            repository_root,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        )

        untracked_paths = sorted(
            path
            for path in untracked_output.split(b"\x00")
            if path
        )

        total_bytes = 0

        for raw_relative_path in untracked_paths:
            relative_path = os.fsdecode(
                raw_relative_path
            )
            absolute_path = (
                repository_root
                / relative_path
            )

            self._update_digest_section(
                digest,
                b"untracked-path",
                raw_relative_path,
            )

            if absolute_path.is_symlink():
                target = os.readlink(
                    absolute_path
                ).encode(
                    "utf-8",
                    errors="surrogateescape",
                )

                self._update_digest_section(
                    digest,
                    b"symlink-target",
                    target,
                )
                continue

            if not absolute_path.is_file():
                self._update_digest_section(
                    digest,
                    b"special-file",
                    b"",
                )
                continue

            file_size = absolute_path.stat().st_size

            if (
                file_size
                > self._maximum_untracked_file_bytes
            ):
                raise ValueError(
                    "An untracked file exceeds the "
                    "revision hashing size limit: "
                    f"{relative_path}"
                )

            total_bytes += file_size

            if (
                total_bytes
                > self._maximum_untracked_total_bytes
            ):
                raise ValueError(
                    "Untracked files exceed the total "
                    "revision hashing size limit."
                )

            self._update_digest_section(
                digest,
                b"untracked-content",
                absolute_path.read_bytes(),
            )

        return digest.hexdigest()

    def _resolve_local_directory(
        self,
        directory: Path,
    ) -> RepositoryContext:
        normalized_path = self._normalized_path(
            directory
        )

        project_id = self._stable_id(
            "project",
            "local_path",
            normalized_path,
        )

        revision_digest = (
            self._local_directory_digest(
                directory
            )
        )

        return RepositoryContext(
            project_id=project_id,
            repository_root=normalized_path,
            identity_source="local_path",
            remote=None,
            branch=None,
            head_commit=None,
            revision=(
                "working-tree:"
                f"{revision_digest}"
            ),
            dirty=True,
        )

    def _local_directory_digest(
        self,
        directory: Path,
    ) -> str:
        digest = hashlib.sha256()
        total_bytes = 0

        entries = sorted(
            path
            for path in directory.rglob("*")
            if ".git" not in path.parts
        )

        for path in entries:
            relative = path.relative_to(directory)
            relative_bytes = os.fsencode(
                relative.as_posix()
            )

            if path.is_symlink():
                self._update_digest_section(
                    digest,
                    b"path",
                    relative_bytes,
                )
                self._update_digest_section(
                    digest,
                    b"symlink",
                    os.fsencode(os.readlink(path)),
                )
                continue

            if not path.is_file():
                continue

            file_size = path.stat().st_size

            if (
                file_size
                > self._maximum_untracked_file_bytes
            ):
                raise ValueError(
                    "A local project file exceeds the "
                    "revision hashing size limit: "
                    f"{relative}"
                )

            total_bytes += file_size

            if (
                total_bytes
                > self._maximum_untracked_total_bytes
            ):
                raise ValueError(
                    "Local project files exceed the total "
                    "revision hashing size limit."
                )

            self._update_digest_section(
                digest,
                b"path",
                relative_bytes,
            )
            self._update_digest_section(
                digest,
                b"content",
                path.read_bytes(),
            )

        return digest.hexdigest()

    @classmethod
    def _canonicalize_remote(
        cls,
        value: str,
    ) -> str:
        remote = value.strip()

        if not remote:
            raise ValueError(
                "Git remote must not be empty."
            )

        scp_match = re.fullmatch(
            r"(?:[^@/\s]+@)?"
            r"(?P<host>[^:/\s]+):"
            r"(?P<path>.+)",
            remote,
        )

        if (
            scp_match is not None
            and "://" not in remote
        ):
            host = (
                scp_match
                .group("host")
                .lower()
            )
            path = scp_match.group("path")

            return cls._canonical_remote_parts(
                host=host,
                path=path,
            )

        parsed = urlsplit(remote)

        if parsed.scheme in {
            "http",
            "https",
            "ssh",
            "git",
        }:
            host = (
                parsed.hostname or ""
            ).lower()

            if not host:
                raise ValueError(
                    "Git remote host is missing."
                )

            return cls._canonical_remote_parts(
                host=host,
                path=parsed.path,
            )

        if parsed.scheme == "file":
            local_path = Path(
                parsed.path
            ).expanduser().resolve()

            return (
                "file://"
                + cls._normalized_path(
                    local_path
                )
            )

        local_candidate = Path(
            remote
        ).expanduser()

        if local_candidate.is_absolute():
            return (
                "file://"
                + cls._normalized_path(
                    local_candidate.resolve()
                )
            )

        raise ValueError(
            "Unsupported Git remote format."
        )

    @staticmethod
    def _canonical_remote_parts(
        *,
        host: str,
        path: str,
    ) -> str:
        normalized_path = (
            path
            .strip()
            .replace("\\", "/")
            .strip("/")
        )

        if normalized_path.endswith(".git"):
            normalized_path = (
                normalized_path[:-4]
            )

        if not normalized_path:
            raise ValueError(
                "Git remote repository path is missing."
            )

        return urlunsplit(
            (
                "https",
                host,
                f"/{normalized_path}",
                "",
                "",
            )
        )

    def _git_repository_root(
        self,
        path: Path,
    ) -> Path | None:
        result = self._run_git(
            path,
            "rev-parse",
            "--show-toplevel",
            check=False,
        )

        if result.returncode != 0:
            return None

        root_text = result.stdout.decode(
            "utf-8",
            errors="replace",
        ).strip()

        if not root_text:
            return None

        return Path(root_text).resolve()

    def _origin_remote(
        self,
        repository_root: Path,
    ) -> str | None:
        return self._optional_git_text(
            repository_root,
            "remote",
            "get-url",
            "origin",
        )

    def _optional_git_text(
        self,
        repository_root: Path,
        *arguments: str,
    ) -> str | None:
        result = self._run_git(
            repository_root,
            *arguments,
            check=False,
        )

        if result.returncode != 0:
            return None

        value = result.stdout.decode(
            "utf-8",
            errors="replace",
        ).strip()

        return value or None

    def _git_bytes(
        self,
        repository_root: Path,
        *arguments: str,
    ) -> bytes:
        return self._run_git(
            repository_root,
            *arguments,
            check=True,
        ).stdout

    @staticmethod
    def _run_git(
        working_directory: Path,
        *arguments: str,
        check: bool,
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.quotepath=false",
                *arguments,
            ],
            cwd=working_directory,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )

        if check and result.returncode != 0:
            stderr = result.stderr.decode(
                "utf-8",
                errors="replace",
            ).strip()

            raise RuntimeError(
                "Git project-identity command failed: "
                + (
                    stderr
                    or f"exit code {result.returncode}"
                )
            )

        return result

    @staticmethod
    def _update_digest_section(
        digest,
        label: bytes,
        content: bytes,
    ) -> None:
        digest.update(
            len(label).to_bytes(
                8,
                byteorder="big",
            )
        )
        digest.update(label)
        digest.update(
            len(content).to_bytes(
                8,
                byteorder="big",
            )
        )
        digest.update(content)

    @staticmethod
    def _normalized_path(
        path: Path,
    ) -> str:
        return path.as_posix()

    @staticmethod
    def _stable_id(
        prefix: str,
        *parts: str,
    ) -> str:
        payload = "\x1f".join(parts)

        digest = hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

        return f"{prefix}:sha256:{digest}"
