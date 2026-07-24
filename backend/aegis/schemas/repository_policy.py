from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from aegis.schemas.policy import PolicyProfile


RuleDecisionOverride = Literal[
    "review",
    "block",
]


class RepositoryRuleOverride(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    decision: RuleDecisionOverride


class RepositoryPolicyWaiver(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    rule_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Z0-9][A-Z0-9_-]*$",
    )
    path: str = Field(
        min_length=1,
        max_length=2_000,
    )
    reason: str = Field(
        min_length=10,
        max_length=2_000,
    )
    expires: date

    @field_validator("path")
    @classmethod
    def validate_path(
        cls,
        value: str,
    ) -> str:
        normalized = value.replace("\\", "/")

        if normalized.startswith("/"):
            raise ValueError(
                "Waiver path must be repository-relative."
            )

        if "\x00" in normalized:
            raise ValueError(
                "Waiver path contains an invalid character."
            )

        parts = normalized.split("/")

        if ".." in parts:
            raise ValueError(
                "Waiver path cannot escape the repository."
            )

        return normalized


class RepositoryPolicyConfig(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    version: Literal[1]

    profile: PolicyProfile | None = None
    fail_on_review: bool | None = None

    rules: dict[
        str,
        RepositoryRuleOverride,
    ] = Field(
        default_factory=dict,
    )

    waivers: list[
        RepositoryPolicyWaiver
    ] = Field(
        default_factory=list,
        max_length=500,
    )

    @field_validator("rules")
    @classmethod
    def validate_rule_ids(
        cls,
        value: dict[
            str,
            RepositoryRuleOverride,
        ],
    ) -> dict[
        str,
        RepositoryRuleOverride,
    ]:
        for rule_id in value:
            if not rule_id:
                raise ValueError(
                    "Rule override ID cannot be empty."
                )

            if len(rule_id) > 200:
                raise ValueError(
                    "Rule override ID is too long."
                )

            if any(
                character
                not in (
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "0123456789_-"
                )
                for character in rule_id
            ):
                raise ValueError(
                    "Rule override IDs must use "
                    "uppercase letters, digits, '_' or '-'."
                )

        return value

    @model_validator(mode="after")
    def reject_duplicate_waivers(
        self,
    ) -> "RepositoryPolicyConfig":
        identities: set[
            tuple[str, str, date]
        ] = set()

        for waiver in self.waivers:
            identity = (
                waiver.rule_id,
                waiver.path,
                waiver.expires,
            )

            if identity in identities:
                raise ValueError(
                    "Duplicate repository policy waiver."
                )

            identities.add(identity)

        return self
