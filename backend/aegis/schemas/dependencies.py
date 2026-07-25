from typing import Literal

from pydantic import BaseModel, Field


DependencyEcosystem = Literal[
    "PyPI",
    "npm",
    "Maven",
    "Go",
    "NuGet",
    "crates.io",
    "Packagist",
]

DependencySeverity = Literal[
    "unknown",
    "low",
    "medium",
    "high",
    "critical",
]

DependencyScanStatus = Literal[
    "completed",
    "partial",
    "failed",
]


class DependencyPackage(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    version: str = Field(min_length=1, max_length=100)
    ecosystem: DependencyEcosystem
    manifest: str = Field(default="unknown", max_length=500)
    direct: bool = True


class DependencyScanRequest(BaseModel):
    packages: list[DependencyPackage] = Field(
        min_length=1,
        max_length=200,
    )


class DependencyManifestInput(BaseModel):
    filename: str = Field(
        min_length=1,
        max_length=300,
    )
    manifest: str = Field(
        min_length=1,
        max_length=500,
    )
    content: str = Field(
        min_length=1,
        max_length=2_000_000,
    )


class DependencyManifestScanRequest(BaseModel):
    manifests: list[DependencyManifestInput] = Field(
        min_length=1,
        max_length=100,
    )


class DependencyVulnerability(BaseModel):
    id: str
    aliases: list[str] = Field(default_factory=list)

    package_name: str
    installed_version: str
    ecosystem: str
    manifest: str
    direct: bool

    summary: str
    details: str = ""

    severity: DependencySeverity = "unknown"
    fixed_versions: list[str] = Field(default_factory=list)

    references: list[str] = Field(default_factory=list)
    published: str | None = None
    modified: str | None = None


class DependencyScanResponse(BaseModel):
    scanner: str
    packages_scanned: int = Field(ge=0)
    successful_packages: int = Field(
        default=0,
        ge=0,
    )
    failed_packages: int = Field(
        default=0,
        ge=0,
    )
    scan_status: DependencyScanStatus = "completed"
    errors: list[str] = Field(
        default_factory=list,
    )
    vulnerable_packages: int = Field(ge=0)
    vulnerabilities: list[DependencyVulnerability]


class DependencyManifestScanResponse(BaseModel):
    packages: list[DependencyPackage]
    scan: DependencyScanResponse
