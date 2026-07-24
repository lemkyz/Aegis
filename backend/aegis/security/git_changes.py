from __future__ import annotations

import subprocess
from pathlib import Path

from aegis.schemas.changes import (
    ChangeFile,
    ChangeFileStatus,
    ChangeSet,
    ChangeSetMode,
)


class GitChangeCollector:
    """
    Collects staged or uncommitted repository changes using
    fixed Git argument arrays. No shell command is executed.
    """

    name = "aegis-git-change-collector-v1"

    _status_map: dict[str, ChangeFileStatus] = {
        "A": "added",
        "M": "modified",
        "D": "deleted",
        "R": "renamed",
        "C": "copied",
        "T": "modified",
    }

    def __init__(
        self,
        *,
        max_files: int = 500,
        max_patch_chars: int = 200_000,
        timeout_seconds: int = 20,
    ) -> None:
        if max_files < 1:
            raise ValueError(
                "max_files must be at least 1"
            )

        if max_patch_chars < 1:
            raise ValueError(
                "max_patch_chars must be at least 1"
            )

        if timeout_seconds < 1:
            raise ValueError(
                "timeout_seconds must be at least 1"
            )

        self.max_files = max_files
        self.max_patch_chars = max_patch_chars
        self.timeout_seconds = timeout_seconds

    def collect(
        self,
        repository_path: str | Path,
        *,
        mode: ChangeSetMode,
    ) -> ChangeSet:
        root = self._repository_root(
            repository_path
        )

        head_revision = self._optional_git(
            root,
            "rev-parse",
            "HEAD",
        )

        base_revision = (
            head_revision
            if mode == "uncommitted"
            else self._optional_git(
                root,
                "rev-parse",
                "HEAD",
            )
        )

        entries = self._tracked_entries(
            root,
            mode=mode,
        )

        if mode == "uncommitted":
            entries.extend(
                (
                    "added",
                    path,
                    None,
                    True,
                )
                for path in self._untracked_paths(root)
            )

        entries = sorted(
            {
                (
                    status,
                    path,
                    old_path,
                    untracked,
                )
                for (
                    status,
                    path,
                    old_path,
                    untracked,
                ) in entries
            },
            key=lambda item: (
                item[1],
                item[0],
                item[2] or "",
            ),
        )

        collection_truncated = (
            len(entries) > self.max_files
        )

        entries = entries[: self.max_files]

        files = [
            self._build_change_file(
                root=root,
                mode=mode,
                status=status,
                path=path,
                old_path=old_path,
                untracked=untracked,
            )
            for (
                status,
                path,
                old_path,
                untracked,
            ) in entries
        ]

        return ChangeSet(
            collector=self.name,
            repository_root=str(root),
            mode=mode,
            base_revision=base_revision,
            head_revision=head_revision,
            files=files,
            file_count=len(files),
            additions=sum(
                item.additions
                for item in files
            ),
            deletions=sum(
                item.deletions
                for item in files
            ),
            truncated=collection_truncated,
        )

    def _tracked_entries(
        self,
        root: Path,
        *,
        mode: ChangeSetMode,
    ) -> list[
        tuple[
            ChangeFileStatus,
            str,
            str | None,
            bool,
        ]
    ]:
        arguments = [
            "diff",
            "--name-status",
            "-z",
            "--diff-filter=ACDMRT",
        ]

        if mode == "staged":
            arguments.insert(1, "--cached")
        else:
            arguments.append("HEAD")

        output = self._git_bytes(
            root,
            *arguments,
        )

        tokens = [
            token.decode(
                "utf-8",
                errors="surrogateescape",
            )
            for token in output.split(b"\0")
            if token
        ]

        entries: list[
            tuple[
                ChangeFileStatus,
                str,
                str | None,
                bool,
            ]
        ] = []

        index = 0

        while index < len(tokens):
            raw_status = tokens[index]
            index += 1

            status_code = raw_status[:1]

            if status_code not in self._status_map:
                raise RuntimeError(
                    "Git returned an unsupported "
                    f"change status: {raw_status}"
                )

            status = self._status_map[
                status_code
            ]

            if status in {"renamed", "copied"}:
                if index + 1 >= len(tokens):
                    raise RuntimeError(
                        "Git returned an incomplete "
                        "rename or copy record."
                    )

                old_path = tokens[index]
                path = tokens[index + 1]
                index += 2

                entries.append(
                    (
                        status,
                        path,
                        old_path,
                        False,
                    )
                )
                continue

            if index >= len(tokens):
                raise RuntimeError(
                    "Git returned an incomplete "
                    "change record."
                )

            path = tokens[index]
            index += 1

            entries.append(
                (
                    status,
                    path,
                    None,
                    False,
                )
            )

        return entries

    def _untracked_paths(
        self,
        root: Path,
    ) -> list[str]:
        output = self._git_bytes(
            root,
            "ls-files",
            "-z",
            "--others",
            "--exclude-standard",
        )

        return sorted(
            token.decode(
                "utf-8",
                errors="surrogateescape",
            )
            for token in output.split(b"\0")
            if token
        )

    def _build_change_file(
        self,
        *,
        root: Path,
        mode: ChangeSetMode,
        status: ChangeFileStatus,
        path: str,
        old_path: str | None,
        untracked: bool,
    ) -> ChangeFile:
        if untracked:
            return self._untracked_change(
                root=root,
                path=path,
            )

        diff_arguments = [
            "diff",
            "--no-ext-diff",
            "--no-color",
            "--unified=3",
        ]

        numstat_arguments = [
            "diff",
            "--numstat",
        ]

        if mode == "staged":
            diff_arguments.insert(
                1,
                "--cached",
            )
            numstat_arguments.insert(
                1,
                "--cached",
            )
        else:
            diff_arguments.append("HEAD")
            numstat_arguments.append("HEAD")

        diff_arguments.extend(
            ["--", path]
        )
        numstat_arguments.extend(
            ["--", path]
        )

        raw_patch = self._git_bytes(
            root,
            *diff_arguments,
        )

        binary = b"\0" in raw_patch

        patch = (
            ""
            if binary
            else raw_patch.decode(
                "utf-8",
                errors="replace",
            )
        )

        patch, truncated = self._truncate_patch(
            patch
        )

        additions, deletions = (
            self._numstat(
                root,
                *numstat_arguments,
            )
        )

        return ChangeFile(
            path=path,
            old_path=old_path,
            status=status,
            patch=patch,
            additions=additions,
            deletions=deletions,
            binary=binary,
            truncated=truncated,
        )

    def _untracked_change(
        self,
        *,
        root: Path,
        path: str,
    ) -> ChangeFile:
        absolute_path = (
            root / path
        ).resolve()

        try:
            absolute_path.relative_to(
                root.resolve()
            )
        except ValueError as exc:
            raise RuntimeError(
                "Untracked path escaped the "
                "repository root."
            ) from exc

        raw_content = absolute_path.read_bytes()
        binary = b"\0" in raw_content

        if binary:
            patch = ""
            additions = 0
        else:
            content = raw_content.decode(
                "utf-8",
                errors="replace",
            )
            additions = len(
                content.splitlines()
            )

            prefixed = "\n".join(
                f"+{line}"
                for line in content.splitlines()
            )

            patch = (
                f"diff --git a/{path} b/{path}\n"
                "new file mode 100644\n"
                "--- /dev/null\n"
                f"+++ b/{path}\n"
                f"@@ -0,0 +1,{additions} @@\n"
                f"{prefixed}"
            )

        patch, truncated = self._truncate_patch(
            patch
        )

        return ChangeFile(
            path=path,
            status="added",
            patch=patch,
            additions=additions,
            deletions=0,
            binary=binary,
            truncated=truncated,
        )

    def _numstat(
        self,
        root: Path,
        *arguments: str,
    ) -> tuple[int, int]:
        output = self._git_text(
            root,
            *arguments,
        )

        additions = 0
        deletions = 0

        for line in output.splitlines():
            parts = line.split(
                "\t",
                maxsplit=2,
            )

            if len(parts) < 2:
                continue

            if parts[0] == "-" or parts[1] == "-":
                continue

            additions += int(parts[0])
            deletions += int(parts[1])

        return additions, deletions

    def _truncate_patch(
        self,
        patch: str,
    ) -> tuple[str, bool]:
        if len(patch) <= self.max_patch_chars:
            return patch, False

        return (
            patch[: self.max_patch_chars],
            True,
        )

    def _repository_root(
        self,
        repository_path: str | Path,
    ) -> Path:
        candidate = Path(
            repository_path
        ).expanduser()

        if not candidate.exists():
            raise ValueError(
                "Repository path does not exist."
            )

        root_output = self._git_text(
            candidate,
            "rev-parse",
            "--show-toplevel",
        ).strip()

        if not root_output:
            raise ValueError(
                "Path is not inside a Git repository."
            )

        return Path(root_output).resolve()

    def _optional_git(
        self,
        root: Path,
        *arguments: str,
    ) -> str | None:
        try:
            value = self._git_text(
                root,
                *arguments,
            ).strip()
        except RuntimeError:
            return None

        return value or None

    def _git_text(
        self,
        root: Path,
        *arguments: str,
    ) -> str:
        return self._git_bytes(
            root,
            *arguments,
        ).decode(
            "utf-8",
            errors="replace",
        )

    def _git_bytes(
        self,
        root: Path,
        *arguments: str,
    ) -> bytes:
        try:
            result = subprocess.run(
                ["git", *arguments],
                cwd=root,
                check=False,
                capture_output=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "Git change collection timed out."
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                "Git executable is unavailable."
            ) from exc

        if result.returncode != 0:
            detail = result.stderr.decode(
                "utf-8",
                errors="replace",
            ).strip()

            raise RuntimeError(
                "Git change collection failed"
                + (
                    f": {detail}"
                    if detail
                    else "."
                )
            )

        return result.stdout
