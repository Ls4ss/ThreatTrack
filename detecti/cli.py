#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Ensure project root is in sys.path when running cli.py directly
_proj_root = str(Path(__file__).resolve().parent)
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

from typing import List, Optional
import click
import typer
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Click 8.3+ compatibility patch for Typer help formatting
_orig_make_metavar = click.Option.make_metavar


def _compat_make_metavar(self, ctx=None):
    if ctx is None:
        try:
            return _orig_make_metavar(self, None)
        except TypeError:
            return self.name.upper() if self.name else "TEXT"
    return _orig_make_metavar(self, ctx)


click.Option.make_metavar = _compat_make_metavar

import importlib.metadata
try:
    __version__ = importlib.metadata.version("detecti-cli")
except importlib.metadata.PackageNotFoundError:
    __version__ = "dev"

from detecti.config import settings, DETECTI_HOME
from detecti.core.engine import ThreatTrackEngine, DetectIEngine
from detecti.modules.exploitdb import ExploitDBModule
from detecti.reporters.html_reporter import HTMLReporter
from detecti.reporters.json_reporter import JSONReporter
from detecti.reporters.markdown_reporter import MarkdownReporter
from detecti.reporters.csv_reporter import CSVReporter
from detecti.utils.logger import (
    console,
    get_real_ip,
    print_banner,
    print_error,
    print_info,
    print_section_header,
    print_success,
    print_warning,
    render_executive_summary,
    render_scan_output,
    render_summary_panel,
)

# Print banner on --help as well
_orig_format_help = click.Command.format_help


def _banner_format_help(self, ctx, formatter):
    print_banner()
    return _orig_format_help(self, ctx, formatter)


click.Command.format_help = _banner_format_help

# Hardcode cli_name for global wrapper execution
cli_name = "detecti-cli"

app = typer.Typer(
    name=cli_name,
    help="DetecTI-CLI: External Attack Surface Mapping & Threat Intelligence Engine",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode=None,
)

# Create hound subcommand group (Interactive EASM Attack Surface Graph Dashboard)
hound_app = typer.Typer(
    name="hound",
    help="DetecTIHound - Interactive EASM Attack Surface Graph Dashboard management",
    add_completion=False,
)
app.add_typer(hound_app, name="hound")

@app.callback(invoke_without_command=True)
def global_callback(ctx: typer.Context):
    """Global callback to execute logic before subcommands."""
    # Check for updates only if a command is actually going to run
    if ctx.invoked_subcommand is not None:
        try:
            from detecti.utils.updater import check_for_updates
            check_for_updates(__version__)
        except Exception:
            pass



def target_to_db_name(target: str) -> str:
    """Convert target string to a clean SQLite database filename (e.g. example.com.sqlite)."""
    t = target.strip()
    # If target is a file path, use its stem
    if Path(t).is_file() and not t.startswith("http"):
        base = Path(t).stem or "file_target"
        return f"{base}.sqlite"

    try:
        from detecti.core.engine import ThreatTrackEngine
        engine = ThreatTrackEngine()
        meta = engine.parse_target_metadata(t)
        clean_target = meta.get("clean_target") or t
    except Exception:
        clean_target = t

    # Replace invalid/unfriendly path characters while preserving dots, hyphens and underscores
    clean = []
    for c in clean_target:
        if c.isalnum() or c in (".", "-", "_"):
            clean.append(c)
        else:
            clean.append("_")
    cleaned_name = "".join(clean).strip("._-")
    if not cleaned_name:
        cleaned_name = "scan_target"

    if not cleaned_name.endswith(".sqlite"):
        cleaned_name = f"{cleaned_name}.sqlite"
    return cleaned_name


@app.command(name="scan")
def scan_command(
    target: Optional[str] = typer.Option(
        None,
        "-t",
        "--target",
        help="Target IP, CIDR, domain, email, CVE, search query, or targets file (e.g., targets.txt)",
    ),
    output_format: str = typer.Option(
        "table",
        "-o",
        "--format",
        help="Output report format: table, json, markdown, html, csv, all",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "-f",
        "--output-file",
        help="Custom file path to export the report (e.g., report.json, report.md, report.html, or report.csv)",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "-d",
        "--output-dir",
        help="Directory to save generated JSON/Markdown/HTML reports",
    ),
    cvss_filter: Optional[str] = typer.Option(
        None,
        "--cvss",
        help="Filter vulnerabilities by CVSS severity: critical, high, medium, low",
    ),
    create_db: Optional[str] = typer.Option(
        None,
        "--create-db",
        help="Custom name for SQLite database in ./data/dbs/ (optional, defaults to target root)",
    ),
) -> None:
    """Execute complete attack surface mapping and threat intelligence analysis.
    
    Examples:
      {cli_name} scan -t example.com
      {cli_name} scan -t example.com --create-db custom_name
      {cli_name} scan -t 192.168.1.0/24
      {cli_name} scan -t CVE-2021-44228
    """.format(cli_name=cli_name)
    
    # Check if target is provided
    if not target:
        print_banner()
        print_error("Target is required. Use -t/--target to specify a target.")
        print_info("Examples:")
        print_info(f"  {cli_name} scan -t example.com")
        print_info(f"  {cli_name} scan -t targets.txt")
        print_info(f"  {cli_name} scan -t 192.168.1.0/24")
        print_info(f"  {cli_name} scan -t CVE-2021-44228")
        print_info(f"Use '{cli_name} scan --help' for more options.")
        raise typer.Exit(1)

    # Pre-validate target before starting scan progress
    try:
        temp_engine = ThreatTrackEngine()
        meta = temp_engine.parse_target_metadata(target)
    except (FileNotFoundError, ValueError) as exc:
        print_banner()
        print_error(str(exc))
        print_info("Target must be a valid IP, CIDR, Domain, URL, CVE, existing File, or Shodan Query filter (e.g., org:'Target', port:443).")
        raise typer.Exit(1)

    print_banner()

    print_section_header("Scan Configuration")
    console.print(f" [cyan]Target:[/cyan] [bold white]{target}[/bold white]")
    if create_db:
        console.print(f" [cyan]Custom DB:[/cyan] [bold white]{create_db}[/bold white]")
    if cvss_filter:
        console.print(f" [cyan]CVSS Filter:[/cyan] [bold yellow]{cvss_filter.upper()}[/bold yellow]")

    # Shift-Left: Initialize Database before scan begins to capture live logs
    is_cve = target.strip().upper().startswith("CVE-")
    db_manager = None
    final_db_name = None
    if not is_cve:
        try:
            from detecti.core.database.storage import DatabaseManager
            if create_db:
                db_name = create_db if create_db.endswith('.sqlite') else f"{create_db}.sqlite"
            else:
                db_name = target_to_db_name(target)
            
            dbs_dir = DETECTI_HOME / "data" / "dbs"
            dbs_dir.mkdir(parents=True, exist_ok=True)
            final_db_path = dbs_dir / db_name
            final_db_name = db_name
            
            db_manager = DatabaseManager(final_db_path)
        except Exception as e:
            print_warning(f"Could not initialize database early: {e}")

    # Run async engine
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task("[bold cyan]Initializing DetecTI-CLI Intelligence Engine...", total=None)

        def progress_cb(module_name: str, message: str) -> None:
            progress.update(task_id, description=f"[bold cyan][{module_name}][/bold cyan] {message}")

        engine = ThreatTrackEngine(progress_callback=progress_cb, db_manager=db_manager)
        result = asyncio.run(
            engine.scan(
                target=target,
                enabled_modules=["all"],
                cvss_filter=cvss_filter,
            )
        )

        # Check if scan yielded any actionable findings / assets
        has_results = (
            (result.summary and (result.summary.total_hosts_count > 0 or result.summary.total_findings > 0))
            or len(result.hosts) > 0
            or len(result.findings) > 0
        )

        # Automatic SQLite database storage for non-CVE targets with valid findings
        if not is_cve and has_results and db_manager:
            try:
                progress.update(task_id, description=f"[bold cyan]Storing results in SQLite database ({final_db_name})...")
                db_manager.store_scan_result(result)
                
                # Lazy Summary: Sync the CLI Executive Summary with the Database Post-Gating metrics
                stats = db_manager.get_summary_stats()
                if result.summary:
                    result.summary.total_hosts_count = stats.get('total_ips', result.summary.total_hosts_count)
                    result.summary.subdomains_count = stats.get('total_subdomains', result.summary.subdomains_count)
                    # For associated domains in UI we refer to total_domains
                    result.summary.associated_domains_count = stats.get('total_domains', result.summary.associated_domains_count)
                    result.summary.open_ports_count = stats.get('open_services', result.summary.open_ports_count)
                    result.summary.vulnerabilities_count = stats.get('total_vulnerabilities', result.summary.vulnerabilities_count)
                    result.summary.cisa_kev_count = stats.get('cisa_kev_count', result.summary.cisa_kev_count)

                print_success(f"Scan results stored in database: [bold underline]{db_manager.db_path.resolve() if hasattr(db_manager.db_path, 'resolve') else db_manager.db_path}[/bold underline]")
            except Exception as e:
                print_error(f"Failed to store results in database: {e}")

            # Automatically launch DetecTIHound WebGUI (only if not already running)
            try:
                from detecti.web.process_manager import WebServerManager
                
                ws_manager = WebServerManager()
                host = "0.0.0.0"
                port = 8000
                real_ip = get_real_ip()

                if ws_manager.is_running():
                    status = ws_manager.get_status() or {}
                    srv_port = status.get("port", port)
                    print_info(f"🌐 DetecTIHound WebGUI is already active (PID: {status.get('pid', 'N/A')}).")
                    console.print(f"  👉 [bold cyan]Local URL:[/bold cyan]   [bold underline cyan]http://localhost:{srv_port}[/bold underline cyan] (Select [bold cyan]{final_db_name or db_name}[/bold cyan] in database dropdown)")
                    console.print(f"  👉 [bold cyan]Network URL:[/bold cyan] [bold underline cyan]http://{real_ip}:{srv_port}[/bold underline cyan]")
                else:
                    started = ws_manager.start_server(final_db_name or db_name, host, port)
                    if started:
                        print_success(f"🚀 DetecTIHound WebGUI started automatically with database: [bold cyan]{final_db_name or db_name}[/bold cyan]")
                        console.print(f"  👉 [bold cyan]Local URL:[/bold cyan]   [bold underline cyan]http://localhost:{port}[/bold underline cyan]")
                        console.print(f"  👉 [bold cyan]Network URL:[/bold cyan] [bold underline cyan]http://{real_ip}:{port}[/bold underline cyan]")
                    else:
                        print_info(f"Open DetecTIHound: [bold cyan]{cli_name} hound start --db {final_db_name or db_name}[/bold cyan]")
            except Exception as e:
                print_warning(f"Could not automatically launch DetecTIHound WebGUI: {e}")
        elif not is_cve and not has_results:
            print_warning(f"No intelligence assets or findings discovered for target '{target}'. SQLite database was not created.")

    # 1. Executive Terminal Output
    if output_format.lower() in ("table", "all") or not output_file:
        render_executive_summary(result)

    # 2. File Export Handling
    safe_target = "".join(c if c.isalnum() else "_" for c in target)[:40]
    timestamp = result.started_at.strftime("%Y%m%d_%H%M%S")

    save_dir = output_dir or Path.cwd()
    save_dir.mkdir(parents=True, exist_ok=True)

    # Determine what to export (supports explicit -o or inferred from -f extension)
    fmt = output_format.lower()
    export_json = fmt in ("json", "all") or (output_file and output_file.suffix == ".json")
    export_md = fmt in ("markdown", "md", "all") or (output_file and output_file.suffix in (".md", ".markdown"))
    export_html = fmt in ("html", "all") or (output_file and output_file.suffix in (".html", ".htm"))
    export_csv = fmt in ("csv", "all") or (output_file and output_file.suffix == ".csv")

    # JSON Export
    if export_json:
        json_path = (
            output_file
            if output_file and output_file.suffix == ".json"
            else save_dir / f"detecti_{safe_target}_{timestamp}.json"
        )
        JSONReporter.save(result, json_path)
        print_success(f"JSON report saved to: [bold underline]{json_path.resolve()}[/bold underline]")

    # CSV Export
    if export_csv:
        csv_path = (
            output_file
            if output_file and output_file.suffix == ".csv"
            else save_dir / f"detecti_{safe_target}_{timestamp}.csv"
        )
        CSVReporter.save(result, csv_path)
        print_success(f"CSV report saved to: [bold underline]{csv_path.resolve()}[/bold underline]")

    # Markdown Export
    if export_md:
        md_path = (
            output_file
            if output_file and output_file.suffix in (".md", ".markdown")
            else save_dir / f"detecti_{safe_target}_{timestamp}.md"
        )
        MarkdownReporter.save(result, md_path)
        print_success(f"Markdown executive report saved to: [bold underline]{md_path.resolve()}[/bold underline]")

    # HTML Export
    if export_html:
        html_path = (
            output_file
            if output_file and output_file.suffix in (".html", ".htm")
            else save_dir / f"detecti_{safe_target}_{timestamp}.html"
        )
        HTMLReporter.save(result, html_path)
        print_success(f"HTML executive report saved to: [bold underline]{html_path.resolve()}[/bold underline]")


@app.command(name="update-xdb")
def update_xdb_command() -> None:
    """Update the local ExploitDB / searchsploit vulnerability mapping database."""
    print_banner()
    print_info("Refreshing ExploitDB database...")
    try:
        ExploitDBModule.update_database()
        print_success("ExploitDB database successfully updated!")
    except Exception as exc:
        print_error(f"Error updating ExploitDB: {exc}")


@app.command(name="config-check")
def config_check_command(
    setup: bool = typer.Option(
        False,
        "--setup",
        "--install",
        "--fix",
        help="Automatically configure prerequisites, install missing dependencies, set capabilities, and update databases",
    ),
) -> None:
    """Check prerequisites, API keys, environment health, or run automated setup."""
    print_banner()

    from detecti.utils.setup import SetupManager
    setup_mgr = SetupManager(console=console)

    if setup:
        setup_mgr.run_automated_setup()

    # 1. System & Environment Health Diagnostics
    print_section_header("System & Environment Diagnostics")
    checks = setup_mgr.check_all()
    setup_mgr.render_diagnostics_table(checks)

    # 2. Live API Verification
    print_section_header("API Credentials & Live Endpoint Verification")
    engine = ThreatTrackEngine()
    api_statuses = asyncio.run(engine.verify_environment_apis())

    for mod_key, info in api_statuses.items():
        name = info.get("name", mod_key.title())
        status = info.get("status", "Unknown")
        if info.get("valid"):
            status_styled = f"[bold green]{status}[/bold green]"
        elif info.get("configured"):
            status_styled = f"[bold red]{status}[/bold red]"
        else:
            status_styled = f"[dim]{status}[/dim]"
        console.print(f" • [cyan]{name}:[/cyan] {status_styled}")

    console.print(f" • [cyan]HTTP Concurrency Limit:[/cyan] {settings.http_concurrency_limit}")
    console.print(f" • [cyan]HTTP Timeout:[/cyan] {settings.http_timeout}s")
    console.print(f" • [cyan]Shodan Rate Limit Delay:[/cyan] {getattr(settings, 'shodan_delay', 1.05)}s")

    needs_setup = not all(c.get("ok", False) for k, c in checks.items() if k != "nuclei")
    if needs_setup and not setup:
        console.print(
            "\n[bold yellow]💡 Tip:[/bold yellow] Run [bold cyan]./detecti-cli setup[/bold cyan] or [bold cyan]./detecti-cli config-check --setup[/bold cyan] to automatically configure missing prerequisites.\n"
        )





@hound_app.command("start")
def start_server(
    db: Optional[str] = typer.Option(
        None,
        "--db",
        "-d",
        help="Target SQLite database file inside ./data/dbs/ or full path (optional, can be selected via UI)",
    ),
    port: int = typer.Option(
        8000,
        "--port",
        "-p",
        help="Port for the HTTP server",
    ),
    host: str = typer.Option(
        "0.0.0.0",
        "--host",
        "-h",
        help="Host binding address",
    ),
) -> None:
    """Start the non-blocking EASM graph webserver in the background."""
    print_banner()
    
    try:
        import fastapi
        import uvicorn
        import psutil
    except ImportError as e:
        print_error("Web server dependencies not installed. Run: pip install fastapi uvicorn psutil")
        return
    
    try:
        from detecti.web.process_manager import WebServerManager
        
        manager = WebServerManager()
        
        # Check if server is already running
        if manager.is_running():
            status = manager.get_status()
            if status:
                print_warning(f"Web server is already running on {status['host']}:{status['port']}")
                print_info(f"Database: {status['db_path']}")
                print_info(f"PID: {status['pid']}")
                return
        
        print_info(f"Starting DetecTI-CLI web server on {host}:{port}...")
        if db:
            print_info(f"Database: {db}")
        else:
            print_info("Database: [italic cyan]Dynamic (selectable via Web UI)[/italic cyan]")
        
        # Start the server
        success = manager.start_server(db, host, port)
        
        if success:
            real_ip = get_real_ip()
            print_success(f"✅ DetecTIHound web server started successfully!")
            console.print(f"  👉 [bold cyan]Local Access:[/bold cyan]   [bold underline cyan]http://localhost:{port}[/bold underline cyan]")
            console.print(f"  👉 [bold cyan]Network Access:[/bold cyan] [bold underline cyan]http://{real_ip}:{port}[/bold underline cyan]")
            if db:
                print_info(f"📊 Initial Database: {db}")
            else:
                print_info(f"📊 Database: Dynamic selector active in Web UI")
            print_info(f"🔧 Use '{cli_name} hound status' to check server status")
            print_info(f"🛑 Use '{cli_name} hound stop' to stop the server")
        else:
            print_error("❌ Failed to start web server")
            print_info("Check that the port is available and dependencies are installed")
            
    except FileNotFoundError as e:
        print_error(f"Database file not found: {e}")
    except Exception as e:
        print_error(f"Failed to start server: {e}")


@hound_app.command("status")
def server_status() -> None:
    """Check the status of the background webserver."""
    print_banner()
    
    try:
        import psutil
    except ImportError:
        print_error("Web server dependencies not installed. Run: pip install fastapi uvicorn psutil")
        return
    
    try:
        from detecti.web.process_manager import WebServerManager
        from rich.table import Table
        
        manager = WebServerManager()
        status = manager.get_status()
        
        if status:
            print_section_header("Web Server Status")
            
            # Create status table
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Property", style="bold white")
            table.add_column("Value", style="green")
            
            real_ip = get_real_ip()
            table.add_row("Status", "🟢 RUNNING")
            table.add_row("PID", str(status['pid']))
            table.add_row("Local URL", f"http://localhost:{status['port']}")
            table.add_row("Network URL", f"http://{real_ip}:{status['port']}")
            table.add_row("Database", status['db_path'])
            table.add_row("Started At", status.get('started_at', 'Unknown'))
            
            if 'uptime_seconds' in status:
                uptime = int(status['uptime_seconds'])
                hours, remainder = divmod(uptime, 3600)
                minutes, seconds = divmod(remainder, 60)
                uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                table.add_row("Uptime", uptime_str)
            
            if 'memory_mb' in status:
                table.add_row("Memory Usage", f"{status['memory_mb']:.1f} MB")
            
            console.print(table)
            print_success(f"🌐 Access Dashboard: [bold underline cyan]http://localhost:{status['port']}[/bold underline cyan] | [bold underline cyan]http://{real_ip}:{status['port']}[/bold underline cyan]")
        else:
            print_warning("🔴 Web server is not running")
            print_info(f"Use '{cli_name} hound start' to start the server")
            
    except Exception as e:
        print_error(f"Failed to check server status: {e}")


@hound_app.command("stop")
def stop_server() -> None:
    """Stop the background webserver gracefully."""
    print_banner()
    
    try:
        import psutil
    except ImportError:
        print_error("Web server dependencies not installed. Run: pip install psutil")
        return
    
    try:
        from detecti.web.process_manager import WebServerManager
        
        manager = WebServerManager()
        
        if not manager.is_running():
            print_warning("🔴 Web server is not running")
            return
        
        print_info("🛑 Stopping web server...")
        
        if manager.stop_server():
            print_success("✅ Web server stopped successfully")
        else:
            print_error("❌ Failed to stop web server")
            
    except Exception as e:
        print_error(f"Failed to stop server: {e}")


@hound_app.command("list-dbs")
def list_databases() -> None:
    """List all available EASM target SQLite databases in ./data/dbs/."""
    print_banner()
    
    data_dir = DETECTI_HOME / "data" / "dbs"
    if not data_dir.exists():
        print_warning("No databases directory found. Run a scan with --persist to create databases.")
        return
    
    db_files = list(data_dir.glob("*.sqlite"))
    if not db_files:
        print_warning("No SQLite databases found in ./data/dbs/")
        return
    
    print_section_header(f"Available EASM Databases ({len(db_files)} found)")
    
    from rich.table import Table
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Database File", style="bold white")
    table.add_column("Target", style="cyan")
    table.add_column("Size", style="dim")
    table.add_column("Modified", style="dim")
    
    for db_file in sorted(db_files):
        size_mb = db_file.stat().st_size / (1024 * 1024)
        modified = db_file.stat().st_mtime
        from datetime import datetime
        mod_time = datetime.fromtimestamp(modified).strftime("%Y-%m-%d %H:%M")
        
        # Try to get target from database
        target = "Unknown"
        try:
            from detecti.core.database.storage import DatabaseManager
            db_manager = DatabaseManager(db_file)
            stats = db_manager.get_summary_stats()
            if 'target' in stats:
                target = stats['target']
        except Exception:
            pass
        
        table.add_row(
            db_file.name,
            target,
            f"{size_mb:.2f} MB",
            mod_time
        )
    
    console.print(table)
    print_info(f"Use '{cli_name} hound start' to start the web dashboard (select database in UI)")


@app.command(name="version")
def version_command() -> None:
    """Show DetecTI-CLI version and maintainer information."""
    console.print(f"[bold cyan]DetecTI-CLI[/bold cyan] version [bold white]{__version__}[/bold white] - Cyber Lead Intelligence Engine")
    console.print("[dim]Developed by Lucas S. (Ls4ss) - https://lucassouza.io[/dim]")


def main() -> None:
    """Main CLI entry point."""
    app(prog_name="detecti-cli")


if __name__ == "__main__":
    main()
