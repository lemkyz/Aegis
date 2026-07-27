import asyncio
import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from aegis.schemas.dependencies import (
    DependencyPackage,
    DependencyScanResponse,
    DependencySeverity,
    DependencyVulnerability,
)


class OsvDependencyScanner:
    api_url = "https://api.osv.dev/v1/query"

    _severity_rank: dict[DependencySeverity, int] = {
        "unknown": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def __init__(self) -> None:
        self.name = "osv"

    async def scan(
        self,
        packages: list[DependencyPackage],
    ) -> DependencyScanResponse:
        tasks = [
            self._query_package(package)
            for package in packages
        ]

        package_results = await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        vulnerabilities: list[DependencyVulnerability] = []
        successful_packages = 0
        errors: list[str] = []

        for package, result in zip(
            packages,
            package_results,
            strict=True,
        ):
            if isinstance(result, Exception):
                package_identifier = (
                    f"{package.ecosystem}/{package.name}"
                    f"@{package.version}"
                )

                error_message = (
                    "OSV dependency query failed for "
                    f"{package_identifier}: {result}"
                )

                print(error_message)

                errors.append(
                    error_message[:1_000]
                )
                continue

            successful_packages += 1
            vulnerabilities.extend(result)

        vulnerabilities = self._deduplicate_vulnerabilities(
            vulnerabilities
        )

        failed_packages = (
            len(packages)
            - successful_packages
        )

        if failed_packages == 0:
            scan_status = "completed"
        elif successful_packages == 0:
            scan_status = "failed"
        else:
            scan_status = "partial"

        vulnerable_packages = len(
            {
                (
                    item.ecosystem,
                    item.package_name.lower(),
                    item.installed_version,
                )
                for item in vulnerabilities
            }
        )

        return DependencyScanResponse(
            scanner=self.name,
            packages_scanned=len(packages),
            successful_packages=successful_packages,
            failed_packages=failed_packages,
            scan_status=scan_status,
            errors=errors,
            vulnerable_packages=vulnerable_packages,
            vulnerabilities=vulnerabilities,
        )

    async def _query_package(
        self,
        package: DependencyPackage,
    ) -> list[DependencyVulnerability]:
        payload = {
            "version": package.version,
            "package": {
                "name": package.name,
                "ecosystem": package.ecosystem,
            },
        }

        response = await asyncio.to_thread(
            self._post_json,
            payload,
        )

        return [
            self._normalize_vulnerability(
                vulnerability,
                package,
            )
            for vulnerability in response.get("vulns", [])
        ]

    def _post_json(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")

        request = Request(
            self.api_url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Aegis-Security/0.2.0",
            },
        )

        try:
            with urlopen(request, timeout=20) as response:
                return json.loads(
                    response.read().decode("utf-8")
                )
        except HTTPError as exc:
            error_body = exc.read().decode(
                "utf-8",
                errors="replace",
            )

            raise RuntimeError(
                f"OSV returned HTTP {exc.code}: "
                f"{error_body}"
            ) from exc
        except URLError as exc:
            raise RuntimeError(
                f"OSV network request failed: {exc.reason}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "OSV returned invalid JSON."
            ) from exc

    @classmethod
    def _normalize_vulnerability(
        cls,
        vulnerability: dict[str, Any],
        package: DependencyPackage,
    ) -> DependencyVulnerability:
        references = [
            str(reference.get("url", "")).strip()
            for reference in vulnerability.get(
                "references",
                [],
            )
            if str(reference.get("url", "")).strip()
        ]

        return DependencyVulnerability(
            id=str(
                vulnerability.get("id", "UNKNOWN")
            ),
            aliases=[
                str(alias)
                for alias in vulnerability.get(
                    "aliases",
                    [],
                )
            ],
            package_name=package.name,
            installed_version=package.version,
            ecosystem=package.ecosystem,
            manifest=package.manifest,
            direct=package.direct,
            summary=str(
                vulnerability.get(
                    "summary",
                    "Known dependency vulnerability",
                )
            ),
            details=str(
                vulnerability.get("details", "")
            ),
            severity=cls._extract_severity(
                vulnerability
            ),
            fixed_versions=cls._extract_fixed_versions(
                vulnerability,
                package,
            ),
            references=references[:20],
            published=vulnerability.get("published"),
            modified=vulnerability.get("modified"),
        )

    @classmethod
    def _deduplicate_vulnerabilities(
        cls,
        vulnerabilities: list[DependencyVulnerability],
    ) -> list[DependencyVulnerability]:
        groups: list[list[DependencyVulnerability]] = []

        for vulnerability in vulnerabilities:
            identifiers = cls._identifiers(vulnerability)

            matching_indexes: list[int] = []

            for index, group in enumerate(groups):
                if not cls._same_package(
                    vulnerability,
                    group[0],
                ):
                    continue

                group_identifiers = set().union(
                    *(
                        cls._identifiers(item)
                        for item in group
                    )
                )

                if identifiers & group_identifiers:
                    matching_indexes.append(index)

            if not matching_indexes:
                groups.append([vulnerability])
                continue

            target_index = matching_indexes[0]
            groups[target_index].append(vulnerability)

            for merge_index in reversed(
                matching_indexes[1:]
            ):
                groups[target_index].extend(
                    groups.pop(merge_index)
                )

        merged = [
            cls._merge_group(group)
            for group in groups
        ]

        return sorted(
            merged,
            key=lambda item: (
                -cls._severity_rank[item.severity],
                item.package_name.lower(),
                item.id,
            ),
        )

    @staticmethod
    def _same_package(
        left: DependencyVulnerability,
        right: DependencyVulnerability,
    ) -> bool:
        return (
            left.ecosystem == right.ecosystem
            and left.package_name.lower()
            == right.package_name.lower()
            and left.installed_version
            == right.installed_version
        )

    @staticmethod
    def _identifiers(
        vulnerability: DependencyVulnerability,
    ) -> set[str]:
        return {
            identifier.upper()
            for identifier in [
                vulnerability.id,
                *vulnerability.aliases,
            ]
            if identifier.strip()
        }

    @classmethod
    def _merge_group(
        cls,
        group: list[DependencyVulnerability],
    ) -> DependencyVulnerability:
        strongest = max(
            group,
            key=lambda item: (
                cls._severity_rank[item.severity],
                len(item.summary),
                len(item.details),
            ),
        )

        all_identifiers = sorted(
            set().union(
                *(
                    cls._identifiers(item)
                    for item in group
                )
            )
        )

        preferred_id = cls._preferred_identifier(
            all_identifiers
        )

        aliases = [
            identifier
            for identifier in all_identifiers
            if identifier != preferred_id
        ]

        fixed_versions = cls._sort_versions(
            {
                version
                for item in group
                for version in item.fixed_versions
                if cls._looks_like_version(version)
            }
        )

        references = list(
            dict.fromkeys(
                reference
                for item in group
                for reference in item.references
            )
        )

        published_values = [
            item.published
            for item in group
            if item.published
        ]

        modified_values = [
            item.modified
            for item in group
            if item.modified
        ]

        return DependencyVulnerability(
            id=preferred_id,
            aliases=aliases,
            package_name=strongest.package_name,
            installed_version=strongest.installed_version,
            ecosystem=strongest.ecosystem,
            manifest=strongest.manifest,
            direct=any(item.direct for item in group),
            summary=strongest.summary,
            details=strongest.details,
            severity=strongest.severity,
            fixed_versions=fixed_versions,
            references=references[:20],
            published=(
                min(published_values)
                if published_values
                else None
            ),
            modified=(
                max(modified_values)
                if modified_values
                else None
            ),
        )

    @staticmethod
    def _preferred_identifier(
        identifiers: Iterable[str],
    ) -> str:
        values = list(identifiers)

        priorities = (
            "GHSA-",
            "CVE-",
            "PYSEC-",
            "OSV-",
        )

        for prefix in priorities:
            candidates = sorted(
                value
                for value in values
                if value.startswith(prefix)
            )

            if candidates:
                return candidates[0]

        return sorted(values)[0] if values else "UNKNOWN"

    @staticmethod
    def _looks_like_version(
        value: str,
    ) -> bool:
        return bool(
            re.fullmatch(
                r"\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?",
                value,
            )
        )

    @staticmethod
    def _sort_versions(
        versions: set[str],
    ) -> list[str]:
        def version_key(value: str) -> tuple[Any, ...]:
            parts = re.split(r"[.-]", value)

            return tuple(
                int(part)
                if part.isdigit()
                else part.lower()
                for part in parts
            )

        try:
            return sorted(versions, key=version_key)
        except TypeError:
            return sorted(versions)

    @staticmethod
    def _extract_severity(
        vulnerability: dict[str, Any],
    ) -> DependencySeverity:
        database_specific = vulnerability.get(
            "database_specific",
            {},
        )

        raw_severity = str(
            database_specific.get("severity", "")
        ).strip().lower()

        aliases = {
            "moderate": "medium",
            "important": "high",
        }

        normalized = aliases.get(
            raw_severity,
            raw_severity,
        )

        if normalized in {
            "low",
            "medium",
            "high",
            "critical",
        }:
            return normalized  # type: ignore[return-value]

        return "unknown"

    @staticmethod
    def _extract_fixed_versions(
        vulnerability: dict[str, Any],
        package: DependencyPackage,
    ) -> list[str]:
        fixed_versions: set[str] = set()

        for affected in vulnerability.get(
            "affected",
            [],
        ):
            affected_package = affected.get(
                "package",
                {},
            )

            if (
                affected_package.get("name")
                != package.name
                or affected_package.get("ecosystem")
                != package.ecosystem
            ):
                continue

            for version_range in affected.get(
                "ranges",
                [],
            ):
                for event in version_range.get(
                    "events",
                    [],
                ):
                    fixed = event.get("fixed")

                    if fixed:
                        fixed_versions.add(str(fixed))

        return sorted(fixed_versions)
