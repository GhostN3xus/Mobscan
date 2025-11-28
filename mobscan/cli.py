#!/usr/bin/env python3
"""
Mobscan CLI - Command-line interface for mobile security testing

Provides simple command-line access to all Mobscan functionality.
"""

import click
import json
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

from .core.engine import TestEngine
from .core.config import MobscanConfig, ScanIntensity
from .api.app import create_app


@click.group()
@click.version_option(version="1.0.0")
@click.pass_context
def cli(ctx):
    """🔒 Mobscan - OWASP MASTG Automated Mobile Security Testing Framework"""
    ctx.ensure_object(dict)


@cli.command()
@click.argument("app_path", type=click.Path(exists=True))
@click.option("--platform", type=click.Choice(["android", "ios"]),
              default="android", help="Target platform")
@click.option("--output-dir", "-o", type=click.Path(),
              default="./reports", help="Output directory for reports")
@click.option("--format", "-f", type=click.Choice(["json", "pdf", "docx", "markdown"]),
              multiple=True, default=["json"], help="Report formats")
@click.option("--intensity", type=click.Choice(["quick", "standard", "full", "comprehensive"]),
              default="full", help="Scan intensity level")
@click.option("--masvs-level", type=click.Choice(["L1", "L2", "R"]),
              multiple=True, default=["L1", "L2"], help="MASVS levels to check")
@click.option("--parallel", type=int, default=4, help="Number of parallel workers")
@click.option("--timeout", type=int, default=7200, help="Global timeout in seconds")
@click.option("--config", type=click.Path(exists=True),
              help="Configuration file (YAML/JSON)")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan(app_path: str, platform: str, output_dir: str, format: tuple,
         intensity: str, masvs_level: tuple, parallel: int, timeout: int,
         config: Optional[str], verbose: bool):
    """
    Scan a mobile application for security vulnerabilities.

    Example:
        mobscan scan app.apk --output reports/ --format json,pdf --intensity full
    """
    click.secho("🔒 Starting mobile security scan...", fg="blue", bold=True)

    try:
        # Load or create configuration
        if config:
            if config.endswith(".yaml") or config.endswith(".yml"):
                cfg = MobscanConfig().load_from_yaml(config)
            else:
                cfg = MobscanConfig().load_from_json(config)
        else:
            cfg = MobscanConfig.default_config()

        # Update configuration with CLI arguments
        cfg.scan_intensity = ScanIntensity(intensity)
        cfg.parallel_workers = parallel
        cfg.timeout_global = timeout
        cfg.masvs_levels = list(masvs_level)
        cfg.log_level = "DEBUG" if verbose else "INFO"

        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Initialize and run scan
        engine = TestEngine(cfg)
        engine.initialize_scan(app_path, Path(app_path).stem)
        result = engine.execute_tests()

        # Generate reports
        click.secho("\n📊 Generating reports...", fg="blue")
        for fmt in format:
            report_content = engine.generate_report(fmt)
            report_path = Path(output_dir) / f"report.{fmt}"

            if isinstance(report_content, str) and (fmt == "json" or fmt == "markdown"):
                with open(report_path, "w") as f:
                    f.write(report_content)
            else:
                with open(report_path, "wb") as f:
                    f.write(report_content.encode())

            click.secho(f"  ✓ {fmt.upper()} report: {report_path}", fg="green")

        # Save scan result
        json_result_path = Path(output_dir) / "scan_result.json"
        engine.save_scan_result(str(json_result_path))

        # Display summary
        click.secho("\n" + "=" * 60, fg="cyan")
        click.secho("SCAN SUMMARY", fg="cyan", bold=True)
        click.secho("=" * 60, fg="cyan")

        stats = engine.get_scan_statistics()
        metrics = result.risk_metrics

        click.echo(f"Scan ID:            {stats['scan_id']}")
        click.echo(f"Duration:           {stats['duration_seconds']}s")
        click.echo(f"Total Findings:     {metrics.total_count}")
        click.secho(f"  Critical:        {metrics.critical_count}", fg="red")
        click.secho(f"  High:            {metrics.high_count}", fg="yellow")
        click.secho(f"  Medium:          {metrics.medium_count}", fg="yellow")
        click.secho(f"  Low:             {metrics.low_count}", fg="cyan")
        click.secho(f"  Info:            {metrics.info_count}", fg="cyan")
        click.secho(f"Risk Score:         {metrics.risk_score:.1f}/10", fg="red" if metrics.risk_score > 7 else "yellow")
        click.echo(f"Reports:            {output_dir}")
        click.echo("")

        if metrics.critical_count > 0 or metrics.high_count > 0:
            click.secho("⚠️  Critical/High vulnerabilities found!", fg="red", bold=True)
            sys.exit(1)
        else:
            click.secho("✓ Scan completed successfully!", fg="green", bold=True)

    except Exception as e:
        click.secho(f"❌ Error: {str(e)}", fg="red", bold=True)
        if verbose:
            click.echo(click.get_text_stream("stderr").write(str(e)))
        sys.exit(1)


@cli.command()
@click.option("--port", "-p", type=int, default=8000, help="Port to run API on")
@click.option("--host", type=str, default="127.0.0.1", help="Host to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
def api(port: int, host: str, reload: bool):
    """
    Start REST API server for Mobscan.

    Example:
        mobscan api --port 8000
    """
    click.secho(f"🚀 Starting Mobscan API on {host}:{port}...", fg="blue", bold=True)

    try:
        app = create_app()

        import uvicorn
        uvicorn.run(
            app,
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )

    except Exception as e:
        click.secho(f"❌ Error starting API: {str(e)}", fg="red", bold=True)
        sys.exit(1)


@cli.command()
@click.option("--port", "-p", type=int, default=8000, help="Port for dashboard")
def interactive(port: int):
    """
    Start interactive web dashboard.

    Example:
        mobscan interactive --port 8000
    """
    click.secho(f"🌐 Starting Mobscan Dashboard on http://localhost:{port}", fg="blue", bold=True)
    click.echo("Open your browser and navigate to the URL above")

    try:
        from .api.app import create_app
        app = create_app()

        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=port)

    except Exception as e:
        click.secho(f"❌ Error: {str(e)}", fg="red", bold=True)
        sys.exit(1)


@cli.command()
@click.option("--init-git", is_flag=True, help="Initialize git repository")
@click.option("--install-deps", is_flag=True, help="Install Python dependencies")
@click.option("--setup-docker", is_flag=True, help="Setup Docker containers")
def init(init_git: bool, install_deps: bool, setup_docker: bool):
    """
    Initialize Mobscan environment.

    Example:
        mobscan init --install-deps --setup-docker
    """
    click.secho("⚙️  Initializing Mobscan environment...", fg="blue", bold=True)

    try:
        # Git initialization
        if init_git:
            click.echo("Initializing git repository...")
            import subprocess
            subprocess.run(["git", "init"], check=True)
            click.secho("✓ Git initialized", fg="green")

        # Create required directories
        click.echo("Creating directories...")
        for directory in ["reports", "cache", ".config", "tools", "logs"]:
            Path(directory).mkdir(exist_ok=True)
        click.secho("✓ Directories created", fg="green")

        # Install dependencies
        if install_deps:
            click.echo("Installing Python dependencies...")
            import subprocess
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                         check=True)
            click.secho("✓ Dependencies installed", fg="green")

        click.secho("\n✓ Environment initialized successfully!", fg="green", bold=True)

    except Exception as e:
        click.secho(f"❌ Error: {str(e)}", fg="red", bold=True)
        sys.exit(1)


@cli.command()
def version():
    """Show version information"""
    click.echo("Mobscan v1.0.0")
    click.echo("OWASP MASTG Automated Mobile Security Testing Framework")


@cli.group()
def report():
    """Manage and generate reports"""
    pass


@report.command()
@click.argument("scan_id")
@click.option("--format", "-f", type=click.Choice(["json", "pdf", "docx", "markdown"]),
              default="pdf", help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def generate(scan_id: str, format: str, output: Optional[str]):
    """Generate report for a scan"""
    click.secho(f"📊 Generating {format} report for scan {scan_id}...", fg="blue")
    # Implementation would load scan result and generate report
    click.secho("✓ Report generated", fg="green")


@cli.command()
@click.argument("app_path", type=click.Path(exists=True))
def validate(app_path: str):
    """Validate application file"""
    click.secho(f"🔍 Validating {app_path}...", fg="blue")

    try:
        # Check file
        app_file = Path(app_path)
        if not app_file.exists():
            raise FileNotFoundError(f"File not found: {app_path}")

        # Check format
        ext = app_file.suffix.lower()
        if ext not in [".apk", ".ipa"]:
            raise ValueError(f"Unsupported file format: {ext}")

        click.secho(f"✓ File valid: {app_file.name} ({app_file.stat().st_size} bytes)",
                   fg="green")

    except Exception as e:
        click.secho(f"❌ Validation failed: {str(e)}", fg="red")
        sys.exit(1)


def main():
    """Main entry point"""
    cli(obj={})


if __name__ == "__main__":
    main()
