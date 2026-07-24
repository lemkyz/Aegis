from typing import Literal

from pydantic import BaseModel, Field, model_validator


ChangeSetMode = Literal[
    "staged",
    "uncommitted",
    "pull_request",
]

ChangeFileStatus = Literal[
    "added",
    "modified",
    "deleted",
    "renamed",
    "copied",
]


class ChangeFile(BaseModel):
    path: str = Field(
        min_length=1,
        max_length=2_000,
    )
    old_path: str | None = Field(
        default=None,
        max_length=2_000,
    )

    status: ChangeFileStatus

    patch: str = Field(
        default="",
        max_length=250_000,
    )

    additions: int = Field(ge=0)
    deletions: int = Field(ge=0)

    binary: bool = False
    truncated: bool = False

    @model_validator(mode="after")
    def validate_paths(self) -> "ChangeFile":
        if (
            self.status in {"renamed", "copied"}
            and not self.old_path
        ):
            raise ValueError(
                "Renamed and copied files require old_path"
            )

        return self


class ChangeSet(BaseModel):
    collector: str
    schema_version: str = "1.0"

    repository_root: str = Field(
        min_length=1,
        max_length=2_000,
    )
    mode: ChangeSetMode

    base_revision: str | None = Field(
        default=None,
        max_length=200,
    )
    head_revision: str | None = Field(
        default=None,
        max_length=200,
    )

    files: list[ChangeFile] = Field(
        default_factory=list,
    )

    file_count: int = Field(ge=0)
    additions: int = Field(ge=0)
    deletions: int = Field(ge=0)

    truncated: bool = False

    @model_validator(mode="after")
    def validate_summary(self) -> "ChangeSet":
        if self.file_count != len(self.files):
            raise ValueError(
                "file_count must equal the number "
                "of collected files"
            )

        if self.additions != sum(
            item.additions
            for item in self.files
        ):
            raise ValueError(
                "additions must equal file additions"
            )

        if self.deletions != sum(
            item.deletions
            for item in self.files
        ):
            raise ValueError(
                "deletions must equal file deletions"
            )

        return self


class ChangeSetCollectionRequest(BaseModel):
    repository_path: str = Field(
        min_length=1,
        max_length=2_000,
    )
    mode: ChangeSetMode

    base_revision: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
    )
    head_revision: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
    )

    @model_validator(mode="after")
    def validate_revisions(
        self,
    ) -> "ChangeSetCollectionRequest":
        if (
            self.mode == "pull_request"
            and not self.base_revision
        ):
            raise ValueError(
                "pull_request mode requires "
                "base_revision"
            )

        if (
            self.mode != "pull_request"
            and (
                self.base_revision is not None
                or self.head_revision is not None
            )
        ):
            raise ValueError(
                "base_revision and head_revision "
                "are only valid in pull_request mode"
            )

        return self
