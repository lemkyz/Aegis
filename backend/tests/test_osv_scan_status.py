import asyncio
from types import MethodType

from aegis.schemas.dependencies import (
    DependencyPackage,
    DependencyVulnerability,
)
from aegis.security.osv import (
    OsvDependencyScanner,
)


def package(
    name: str,
    version: str = "1.0.0",
) -> DependencyPackage:
    return DependencyPackage(
        name=name,
        version=version,
        ecosystem="npm",
        manifest="package-lock.json",
        direct=True,
    )


def vulnerability(
    dependency: DependencyPackage,
) -> DependencyVulnerability:
    return DependencyVulnerability(
        id="GHSA-test-test-test",
        aliases=["CVE-2099-0001"],
        package_name=dependency.name,
        installed_version=dependency.version,
        ecosystem=dependency.ecosystem,
        manifest=dependency.manifest,
        direct=dependency.direct,
        summary="Test vulnerability.",
        severity="high",
        fixed_versions=["2.0.0"],
    )


def test_osv_scan_reports_completed_status() -> None:
    scanner = OsvDependencyScanner()
    dependency = package("safe-package")

    async def successful_query(
        _self,
        requested_package,
    ):
        assert requested_package == dependency
        return []

    scanner._query_package = MethodType(
        successful_query,
        scanner,
    )

    result = asyncio.run(
        scanner.scan([dependency])
    )

    assert result.scan_status == "completed"
    assert result.packages_scanned == 1
    assert result.successful_packages == 1
    assert result.failed_packages == 0
    assert result.errors == []
    assert result.vulnerabilities == []


def test_osv_scan_reports_partial_status() -> None:
    scanner = OsvDependencyScanner()

    vulnerable_package = package(
        "vulnerable-package",
        "1.0.0",
    )
    unavailable_package = package(
        "unavailable-package",
        "3.0.0",
    )

    async def mixed_query(
        _self,
        requested_package,
    ):
        if (
            requested_package.name
            == "unavailable-package"
        ):
            raise RuntimeError(
                "OSV network request failed"
            )

        return [
            vulnerability(
                requested_package
            )
        ]

    scanner._query_package = MethodType(
        mixed_query,
        scanner,
    )

    result = asyncio.run(
        scanner.scan(
            [
                vulnerable_package,
                unavailable_package,
            ]
        )
    )

    assert result.scan_status == "partial"
    assert result.packages_scanned == 2
    assert result.successful_packages == 1
    assert result.failed_packages == 1
    assert len(result.errors) == 1
    assert "unavailable-package@3.0.0" in (
        result.errors[0]
    )
    assert result.vulnerable_packages == 1
    assert len(result.vulnerabilities) == 1


def test_osv_scan_reports_failed_status() -> None:
    scanner = OsvDependencyScanner()
    dependency = package(
        "unavailable-package",
    )

    async def failed_query(
        _self,
        _requested_package,
    ):
        raise RuntimeError(
            "OSV returned HTTP 503"
        )

    scanner._query_package = MethodType(
        failed_query,
        scanner,
    )

    result = asyncio.run(
        scanner.scan([dependency])
    )

    assert result.scan_status == "failed"
    assert result.packages_scanned == 1
    assert result.successful_packages == 0
    assert result.failed_packages == 1
    assert result.vulnerable_packages == 0
    assert result.vulnerabilities == []
    assert len(result.errors) == 1
    assert "HTTP 503" in result.errors[0]
