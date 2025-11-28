"""
Complete Mobscan Analysis Example

Demonstrates complete integration of all modules for a comprehensive
mobile security assessment.
"""

import sys
from pathlib import Path
import json
import logging

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mobscan.core.analysis_manager import (
    AnalysisManager, AnalysisConfig, AnalysisModule
)
from mobscan.core.rules_engine import RulesEngine
from mobscan.modules.sast.sast_complete import SASTModule
from mobscan.modules.dast.dast_complete import DASTModule
from mobscan.modules.frida.frida_complete import FridaInstrumentationModule
from mobscan.modules.sca.sca_engine import SCAModule


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_modules():
    """Setup all analysis modules"""
    logger.info("Initializing analysis modules...")

    modules = {
        'sast': SASTModule(),
        'dast': DASTModule(),
        'frida': FridaInstrumentationModule(),
        'sca': SCAModule(),
    }

    return modules


def load_rules(rules_file: str) -> RulesEngine:
    """Load vulnerability rules from YAML file"""
    logger.info(f"Loading rules from {rules_file}...")

    engine = RulesEngine()
    rules = engine.load_rules_from_file(rules_file)

    logger.info(f"Loaded {len(rules)} vulnerability rules")
    return engine


def run_comprehensive_analysis(app_path: str, output_file: str = "report.json"):
    """
    Run comprehensive mobile security analysis

    Args:
        app_path: Path to APK or IPA file
        output_file: Output report file

    Returns:
        Analysis results
    """

    # Validate input
    app_file = Path(app_path)
    if not app_file.exists():
        logger.error(f"Application file not found: {app_path}")
        sys.exit(1)

    logger.info(f"Starting comprehensive analysis of {app_file.name}")
    logger.info(f"Application size: {app_file.stat().st_size / (1024*1024):.2f} MB")

    # Configure analysis
    config = AnalysisConfig(
        timeout_per_module=300,
        parallel_execution=True,
        max_workers=4,
        enable_deduplication=True,
        enable_correlation=True,
        enable_severity_scoring=True,
    )

    # Initialize manager
    manager = AnalysisManager(config)

    # Register modules
    modules = setup_modules()
    for module_type, module in modules.items():
        manager.register_module(module)
        logger.info(f"Registered {module_type} module")

    # Prepare module-specific configurations
    module_configs = {
        "sast": {
            "platform": "android" if app_path.endswith(".apk") else "ios",
            "enable_taint_analysis": True,
            "enable_ast_analysis": True,
        },
        "dast": {
            "timeout": 60,
            "fuzz_payloads": True,
        },
        "frida": {
            "platform": "android" if app_path.endswith(".apk") else "ios",
            "scripts": ["ssl_pinning_bypass", "root_detection_bypass", "crypto_monitoring"],
        },
        "sca": {
            "check_vulnerabilities": True,
            "check_licenses": True,
        }
    }

    # Run analysis
    logger.info("Executing analysis pipeline...")
    result = manager.run_analysis(app_path, module_configs)

    # Get statistics
    stats = manager.get_statistics()
    logger.info(f"Analysis completed in {stats['duration_seconds']:.2f} seconds")
    logger.info(f"Total findings: {stats['total_findings']}")
    logger.info(f"Risk score: {stats['risk_score']}/10")

    # Save JSON report
    logger.info(f"Saving report to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)

    return result


def generate_executive_summary(result: dict) -> str:
    """Generate executive summary from analysis results"""

    summary = f"""
╔══════════════════════════════════════════════════════════════════════════╗
║                    MOBSCAN SECURITY ASSESSMENT REPORT                    ║
║                         EXECUTIVE SUMMARY                                ║
╚══════════════════════════════════════════════════════════════════════════╝

ANALYSIS METADATA
─────────────────
Scan ID:              {result.get('scan_id', 'N/A')}
Timestamp:            {result.get('timestamp', 'N/A')}
Duration:             {result.get('duration_seconds', 0):.2f} seconds
Modules Executed:     {', '.join(result.get('modules_executed', []))}

FINDINGS SUMMARY
────────────────
Total Findings:       {result.get('total_findings', 0)}
Risk Score:           {result.get('risk_score', 0.0)}/10.0

SEVERITY DISTRIBUTION
─────────────────────
Critical:             {result.get('severity_distribution', {}).get('critical', 0)}
High:                 {result.get('severity_distribution', {}).get('high', 0)}
Medium:               {result.get('severity_distribution', {}).get('medium', 0)}
Low:                  {result.get('severity_distribution', {}).get('low', 0)}
Info:                 {result.get('severity_distribution', {}).get('info', 0)}

CRITICAL FINDINGS
──────────────────
"""

    findings = result.get('findings', [])
    critical_findings = [f for f in findings if f.get('severity') == 'critical']

    if critical_findings:
        for finding in critical_findings[:5]:  # Show top 5
            summary += f"\n  • {finding.get('title', 'N/A')}"
            summary += f"\n    CVSS: {finding.get('cvss_score', 'N/A')}"
            summary += f"\n    Component: {finding.get('affected_component', 'N/A')}\n"
    else:
        summary += "\n  No critical findings detected\n"

    summary += """
RECOMMENDATIONS
────────────────
1. Address all CRITICAL and HIGH severity findings immediately
2. Implement proper encryption for sensitive data
3. Use secure APIs for authentication and authorization
4. Regular security testing and code reviews
5. Keep dependencies updated and monitor for vulnerabilities

╚══════════════════════════════════════════════════════════════════════════╝
    """

    return summary


def export_technical_report(result: dict, output_file: str = "technical_report.txt"):
    """Generate detailed technical report"""

    report = "MOBSCAN TECHNICAL SECURITY REPORT\n"
    report += "=" * 80 + "\n\n"

    findings = result.get('findings', [])

    # Group by severity
    by_severity = {}
    for finding in findings:
        severity = finding.get('severity', 'unknown')
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)

    # Print findings grouped by severity
    severity_order = ['critical', 'high', 'medium', 'low', 'info']

    for severity in severity_order:
        if severity not in by_severity:
            continue

        findings_list = by_severity[severity]
        report += f"\n{severity.upper()} SEVERITY ({len(findings_list)} findings)\n"
        report += "-" * 80 + "\n\n"

        for i, finding in enumerate(findings_list, 1):
            report += f"{i}. {finding.get('title', 'N/A')}\n"
            report += f"   ID: {finding.get('id', 'N/A')}\n"
            report += f"   Module: {finding.get('module', 'N/A')}\n"
            report += f"   CVSS: {finding.get('cvss_score', 'N/A')}\n"
            report += f"   CWE: {', '.join(finding.get('cwe', []))}\n"
            report += f"   MASVS: {', '.join(finding.get('masvs_mapping', []))}\n"
            report += f"   Component: {finding.get('affected_component', 'N/A')}\n"
            report += f"\n   Description:\n   {finding.get('description', 'N/A')}\n"
            report += f"\n   Remediation:\n   {finding.get('remediation', 'N/A')}\n"
            report += "\n" + "-" * 80 + "\n\n"

    # Write to file
    with open(output_file, 'w') as f:
        f.write(report)

    logger.info(f"Technical report saved to {output_file}")


def main():
    """Main entry point"""

    import argparse

    parser = argparse.ArgumentParser(
        description='Mobscan - Enterprise Mobile Security Automation'
    )
    parser.add_argument('app_path', help='Path to APK or IPA file')
    parser.add_argument(
        '--output', '-o',
        default='mobscan_report.json',
        help='Output report file (default: mobscan_report.json)'
    )
    parser.add_argument(
        '--technical',
        default='technical_report.txt',
        help='Technical report file (default: technical_report.txt)'
    )

    args = parser.parse_args()

    # Run analysis
    result = run_comprehensive_analysis(args.app_path, args.output)

    # Generate reports
    logger.info("Generating reports...")

    # Executive summary
    exec_summary = generate_executive_summary(result)
    print(exec_summary)

    # Technical report
    export_technical_report(result, args.technical)

    logger.info("Analysis complete!")
    logger.info(f"JSON report: {args.output}")
    logger.info(f"Technical report: {args.technical}")


if __name__ == "__main__":
    main()
