#!/usr/bin/env python3
"""
Example Usage of Mobscan Framework

This example demonstrates how to use Mobscan programmatically
for mobile application security testing.
"""

from pathlib import Path
import json

from mobscan.core.engine import TestEngine
from mobscan.core.config import MobscanConfig, ScanIntensity
from mobscan.models.finding import Finding, Severity, CVSSScore, Evidence, Remediation


def example_1_basic_scan():
    """Example 1: Basic scan with default configuration"""
    print("=" * 60)
    print("Example 1: Basic Scan")
    print("=" * 60)

    # Create config
    config = MobscanConfig.default_config()
    config.scan_intensity = ScanIntensity.FULL

    # Create engine
    engine = TestEngine(config)

    # Initialize scan
    app_path = "builds/app.apk"
    result = engine.initialize_scan(app_path, "DemoApp")

    print(f"Scan ID: {result.scan_id}")
    print(f"App: {result.app_info.app_name}")
    print(f"Platform: {result.app_info.platform}")


def example_2_custom_config():
    """Example 2: Scan with custom configuration"""
    print("\n" + "=" * 60)
    print("Example 2: Custom Configuration")
    print("=" * 60)

    # Load from YAML (if file exists)
    config = MobscanConfig.default_config()

    # Customize
    config.scan_intensity = ScanIntensity.COMPREHENSIVE
    config.parallel_workers = 8
    config.masvs_levels = ["L1", "L2", "R"]
    config.log_level = "DEBUG"

    print(f"Intensity: {config.scan_intensity.value}")
    print(f"Workers: {config.parallel_workers}")
    print(f"MASVS Levels: {config.masvs_levels}")


def example_3_manual_findings():
    """Example 3: Create findings programmatically"""
    print("\n" + "=" * 60)
    print("Example 3: Manual Finding Creation")
    print("=" * 60)

    # Create a finding
    finding = Finding(
        id="FINDING-EXAMPLE-001",
        title="Hardcoded API Key",
        description="API key found hardcoded in source code",
        severity=Severity.CRITICAL,
        cvss=CVSSScore(
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ),
        cwe=["CWE-798", "CWE-321"],
        owasp_category="A02:2021 - Cryptographic Failures",
        test_name="Hardcoded Secrets Scan",
        module="sast",
        mastg_category="MASTG-STORAGE-1",
        masvs_category="MSTG-STORAGE-1",
        affected_component="NetworkManager.java",
        affected_code_location="com/example/app/NetworkManager.java:42"
    )

    # Add evidence
    evidence = Evidence(
        type="code",
        content="private static final String API_KEY = \"sk-1234567890abcdef\";",
        metadata={"line_number": 42, "file": "NetworkManager.java"}
    )
    finding.add_evidence(evidence)

    # Add remediation
    remediation = Remediation(
        short_description="Remove hardcoded credentials",
        detailed_steps=[
            "1. Move API key to secure configuration",
            "2. Use environment variables or secure storage",
            "3. Implement proper key rotation",
            "4. Remove from version control"
        ],
        code_example="""
// Bad (DO NOT USE)
private static final String API_KEY = "secret-key";

// Good
private String getApiKey() {
    return BuildConfig.API_KEY;  // From build config
}
""",
        references=[
            "https://owasp.org/www-community/Hardcoded_database_connection_string",
            "https://developer.android.com/training/articles/keystore"
        ],
        effort="Low"
    )
    finding.set_remediation(remediation)

    print(f"Finding: {finding.title}")
    print(f"Severity: {finding.severity.value}")
    print(f"CVSS Score: {finding.cvss.score}")
    print(f"Evidence Count: {len(finding.evidence)}")


def example_4_scan_workflow():
    """Example 4: Complete scan workflow"""
    print("\n" + "=" * 60)
    print("Example 4: Complete Scan Workflow")
    print("=" * 60)

    # Setup
    config = MobscanConfig.default_config()
    engine = TestEngine(config)

    # Initialize
    app_path = "builds/app.apk"
    scan_result = engine.initialize_scan(app_path, "MyApp")

    print(f"✓ Scan initialized: {scan_result.scan_id}")

    # Execute tests
    try:
        scan_result = engine.execute_tests()
        print(f"✓ Tests executed")

        # Display results
        metrics = scan_result.risk_metrics
        print(f"\nFindings Summary:")
        print(f"  Critical: {metrics.critical_count}")
        print(f"  High: {metrics.high_count}")
        print(f"  Medium: {metrics.medium_count}")
        print(f"  Low: {metrics.low_count}")
        print(f"  Risk Score: {metrics.risk_score}/10")

        # Generate reports
        json_report = engine.generate_report("json")
        print(f"\n✓ JSON Report generated")

        md_report = engine.generate_report("markdown")
        print(f"✓ Markdown Report generated")

        # Save results
        output_file = f"reports/scan_{scan_result.scan_id}.json"
        engine.save_scan_result(output_file)
        print(f"✓ Results saved to: {output_file}")

    except Exception as e:
        print(f"✗ Error: {str(e)}")


def example_5_result_analysis():
    """Example 5: Analyze scan results"""
    print("\n" + "=" * 60)
    print("Example 5: Result Analysis")
    print("=" * 60)

    # Load scan result from JSON
    result_file = "reports/scan_result.json"

    if Path(result_file).exists():
        with open(result_file, 'r') as f:
            data = json.load(f)

        print(f"Scan ID: {data['scan_id']}")
        print(f"App: {data['app_info']['app_name']}")
        print(f"Platform: {data['app_info']['platform']}")
        print(f"Total Findings: {data['findings_count']}")

        # Analyze by severity
        critical = data['risk_metrics']['critical']
        high = data['risk_metrics']['high']

        if critical > 0:
            print(f"\n⚠️  CRITICAL findings: {critical}")
        if high > 0:
            print(f"⚠️  HIGH findings: {high}")

        # Show top findings
        print(f"\nTop findings:")
        for i, finding in enumerate(data['findings'][:3], 1):
            print(f"{i}. {finding['title']} ({finding['severity']})")

    else:
        print("No scan results found")


def example_6_filter_findings():
    """Example 6: Filter and group findings"""
    print("\n" + "=" * 60)
    print("Example 6: Filter and Group Findings")
    print("=" * 60)

    # Create sample scan result
    config = MobscanConfig.default_config()
    engine = TestEngine(config)
    scan_result = engine.initialize_scan("builds/app.apk", "TestApp")

    # Add sample findings (simplified)
    finding1 = Finding(
        id="F1", title="Issue 1", description="Test", severity=Severity.CRITICAL,
        cvss=CVSSScore(9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        cwe=[], owasp_category="", test_name="", module="sast",
        mastg_category="MASTG-STORAGE-1", masvs_category="MSTG-STORAGE-1",
        affected_component="Comp1"
    )

    scan_result.add_finding(finding1)

    # Filter by severity
    critical_findings = scan_result.get_findings_by_severity(Severity.CRITICAL)
    print(f"Critical findings: {len(critical_findings)}")

    # Filter by MASTG category
    storage_findings = scan_result.get_findings_by_mastg("MASTG-STORAGE-1")
    print(f"Storage findings: {len(storage_findings)}")

    # Calculate statistics
    print(f"\nStatistics:")
    print(f"Total: {len(scan_result.findings)}")
    print(f"Risk Score: {scan_result.risk_metrics.risk_score}")


if __name__ == "__main__":
    print("Mobscan Framework Examples\n")

    # Run examples
    example_1_basic_scan()
    example_2_custom_config()
    example_3_manual_findings()
    # example_4_scan_workflow()  # Uncomment if app file exists
    # example_5_result_analysis()  # Uncomment if results exist
    example_6_filter_findings()

    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)
