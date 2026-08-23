import asyncio
import hashlib
import json
import os
import sys
import socket
import ipaddress
import contextlib
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from leakradar import __version__
from leakradar.auth import LicenseManager
from leakradar.bola_matrix import BolaMatrixRunner, Finding
from leakradar.markdown_poc import MarkdownPoCExporter
try:
    import reportlab
    import reportlab.lib.colors
    import reportlab.lib.pagesizes
    import reportlab.lib.styles
    import reportlab.platypus
except ImportError:
    pass

try:
    from leakradar.pdf_report import PDFReportGenerator
except ImportError:
    try:
        # Fallback: load from the _pro submodule path (populated by CI deploy key)
        import importlib.util as _ilu, sys as _sys
        from pathlib import Path as _Path
        _pro_path = _Path(__file__).parent / "_pro" / "pdf_report.py"
        if _pro_path.exists():
            _spec = _ilu.spec_from_file_location("leakradar.pdf_report", _pro_path)
            _mod = _ilu.module_from_spec(_spec)
            _sys.modules["leakradar.pdf_report"] = _mod
            _spec.loader.exec_module(_mod)
            PDFReportGenerator = _mod.PDFReportGenerator
        else:
            PDFReportGenerator = None
    except Exception:
        PDFReportGenerator = None

from leakradar.seeder import OpenAPISeeder

app = typer.Typer(
    name="leakradar",
    help="LeakRadar - Open-Core API Security CLI for BOLA/IDOR Vulnerability Scanning",
    add_completion=False,
)
console = Console()


@contextlib.contextmanager
def safe_dns_resolver(allow_internal_host: Optional[str] = None):
    original_getaddrinfo = socket.getaddrinfo
    
    def safe_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        results = original_getaddrinfo(host, port, family, type, proto, flags)
        
        if allow_internal_host and host.lower() == allow_internal_host:
            return results
            
        safe_results = []
        for res in results:
            ip_str = res[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                safe_results.append(res)
                continue
                
            if (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast):
                raise ValueError(f"SSRF Protection blocked connection to restricted IP: {ip_str} for host: {host}")
            
            safe_results.append(res)
            
        if not safe_results:
            raise ValueError(f"No safe IP addresses found for {host}")
        return safe_results

    socket.getaddrinfo = safe_getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo


def _load_openapi_spec(spec_path_or_url: str, allow_internal: bool = False) -> Dict[str, Any]:
    """
    Fetch and parse an OpenAPI specification from a local file or HTTP URL (JSON or YAML).
    """
    content = ""
    if spec_path_or_url.startswith("http://") or spec_path_or_url.startswith("https://"):
        parsed = urllib.parse.urlparse(spec_path_or_url)
        allowed_host = parsed.hostname.lower() if allow_internal and parsed.hostname else None
        
        with safe_dns_resolver(allowed_host):
            with httpx.Client(timeout=15.0, follow_redirects=True) as client:
                try:
                    resp = client.get(spec_path_or_url)
                    resp.raise_for_status()
                    content = resp.text
                except Exception as e:
                    raise ValueError(f"Failed to fetch spec from URL: {e}")
    else:
        p = Path(spec_path_or_url)
        if not p.exists():
            raise FileNotFoundError(f"Spec file not found: {spec_path_or_url}")
        with open(p, "r", encoding="utf-8") as f:
            content = f.read()

    try:
        return json.loads(content)
    except Exception:
        pass

    try:
        return yaml.safe_load(content)
    except Exception as e:
        raise ValueError(f"Failed to parse OpenAPI spec as JSON or YAML: {e}")


def _generate_collision_proof_filename(finding: Finding) -> str:
    """
    Generates a deterministic collision-proof filename using endpoint template and param values hash.
    """
    clean_endpoint = finding.seed.endpoint_template.strip("/").replace("/", "_").replace("{", "").replace("}", "")
    param_str = json.dumps(finding.seed.param_values, sort_keys=True)
    hash_suffix = hashlib.sha256(param_str.encode("utf-8")).hexdigest()[:8]
    return f"bola_{clean_endpoint}_{hash_suffix}"


@app.command("auth")
def auth_command(
    key: str = typer.Option(..., "--key", "-k", help="Dodo Payments License Key to activate")
):
    """
    Activate a paid LeakRadar license key via Dodo Payments.
    """
    console.print(f"[bold blue]Activating LeakRadar license...[/bold blue]")

    async def _act():
        ctx = await LicenseManager.activate_license(key)
        return ctx

    ctx = asyncio.run(_act())

    if ctx.active:
        console.print(
            Panel.fit(
                f"[bold green]License Activated Successfully![/bold green]\n"
                f"Tier: [bold cyan]{ctx.tier.upper()}[/bold cyan]\n"
                f"PDF Export: {'[green]Enabled[/green]' if ctx.capabilities.get('pdf_export') else '[red]Disabled[/red]'}\n"
                f"Cloud Rules: {'[green]Enabled[/green]' if ctx.capabilities.get('cloud_rules') else '[red]Disabled[/red]'}",
                title="LeakRadar Licensing",
            )
        )
    else:
        console.print("[bold red]Error: License activation failed.[/bold red]")


@app.command("scan")
def scan_command(
    base_url: str = typer.Option(..., "--base-url", "-u", help="Base URL of the target REST API"),
    spec: str = typer.Option(..., "--spec", "-s", help="OpenAPI/Swagger spec file path or URL"),
    token_a: str = typer.Option(..., "--token-a", "-a", help="Authorization Header / Token for User A (Resource Owner)"),
    token_b: str = typer.Option(..., "--token-b", "-b", help="Authorization Header / Token for User B (Attacker)"),
    output: str = typer.Option("./findings", "--output", "-o", help="Directory to save report outputs"),
    format_choice: str = typer.Option(
        "markdown", "--format", "-f", help="Output report format choices: markdown, pdf, all"
    ),
    company: Optional[str] = typer.Option(None, "--company", "-c", help="Custom Company / Agency Name for PDF White-Labeling (Pro Feature)"),
    logo: Optional[str] = typer.Option(None, "--logo", "-l", help="Custom Logo File Path for PDF White-Labeling (Pro Feature)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
    allow_destructive: bool = typer.Option(
        False,
        "--allow-destructive",
        help="Allow probing of POST/PUT/PATCH/DELETE state-modifying endpoints during scan",
    ),
    allow_internal_spec: bool = typer.Option(
        False,
        "--allow-internal-spec",
        help="Allow `--spec` to fetch OpenAPI files from loopback, private, or link-local IPs. WARNING: Exposes SSRF if abused.",
    ),
):
    """
    Run an automated BOLA/IDOR vulnerability scan against the target REST API.
    """
    lic_ctx = LicenseManager.get_active_context()

    # Free Tier Rate Limiting & Speed Control
    is_free = lic_ctx.tier.lower() == "free"
    rate_delay = 1.5 if is_free else 0.0

    if allow_destructive:
        console.print(
            Panel.fit(
                "[bold red]WARNING: Destructive method testing enabled. This will send real POST/PUT/PATCH/DELETE requests using User B's credentials against objects belonging to User A. Ensure you have explicit authorization and are not testing against production data you don't control.[/bold red]",
                title="Safety Warning",
            )
        )

    BANNER = (
        "[bold cyan]  _        ______    _    _   _____            _____            _____       _____  [/bold cyan]\n"
        "[bold cyan] | |      |  ____|  / \\  | | / ____|          |  __ \\    /\\    |  __ \\  /\\  |  __ \\ [/bold cyan]\n"
        "[bold cyan] | |      | |__    / _ \\ | || |     _   _ ___ | |__) |  /  \\   | |  | |/  \\ | |__) |[/bold cyan]\n"
        "[bold cyan] | |      |  __|  / ___ \\| || |    | | | / __||  _  /  / /\\ \\  | |  | / /\\ \\|  _  / [/bold cyan]\n"
        "[bold cyan] | |____  | |____/ /   \\ \\ || |____| |_| \\__ \\| | \\ \\ / ____ \\ | |__| / ____ \\ | \\ \\ [/bold cyan]\n"
        "[bold cyan] |______| |______/_/     \\_\\_\\_____|\\__,_|___/|_|  \\_/_/    \\_\\|_____/_/    \\_\\_|  \\_\\[/bold cyan]\n"
        "[dim]                    [ OPEN-CORE API BOLA SECURITY ENGINE ][/dim]\n"
    )
    console.print(BANNER)

    if is_free:
        console.print(
            Panel.fit(
                "[bold yellow]COMMUNITY EDITION (FREE TIER)[/bold yellow]\n"
                "[dim]• Rate Limiting: Active (1.5s request throttling delay per probe)[/dim]\n"
                "[dim]• White-Label PDF Reports: Locked (Requires Pro Auditor License)[/dim]\n"
                "[cyan]Upgrade to Pro Auditor ($30/mo) for maximum speed & executive PDF deliverables.[/cyan]",
                title="LeakRadar Tier Notice",
            )
        )

    console.print(
        Panel.fit(
            f"[bold cyan]LeakRadar API Security Scanner v{__version__}[/bold cyan]\n"
            f"Target Base URL: [bold]{base_url}[/bold]\n"
            f"OpenAPI Spec: [bold]{spec}[/bold]\n"
            f"Scan Speed Mode: {'[yellow]Rate-Limited (Free)[/yellow]' if is_free else '[green]Maximum Speed (Pro)[/green]'}\n"
            f"Method Safety Mode: {'[bold red]Destructive Operations Allowed[/bold red]' if allow_destructive else '[bold green]Safe Mode (GET/HEAD Only)[/bold green]'}",
            title="Scan Initialization",
        )
    )

    if verbose:
        console.print(f"[dim]License status: active={lic_ctx.active}, tier={lic_ctx.tier}[/dim]")

    # Check format permissions
    if format_choice.lower() in ("pdf", "all") and not lic_ctx.capabilities.get("pdf_export", True):
        console.print(
            "[yellow]Warning: PDF export is a paid feature. Free tier will fall back to Markdown export.[/yellow]"
        )

    # 1. Parse OpenAPI Spec
    try:
        spec_data = _load_openapi_spec(spec, allow_internal=allow_internal_spec)
        paths = spec_data.get("paths", {})
        target_name = spec_data.get("info", {}).get("title", "Target REST API")
    except Exception as e:
        console.print(f"[bold red]Failed to load spec:[/bold red] {e}")
        raise typer.Exit(code=1)

    # Prepare Headers
    headers_a = {"Authorization": token_a if token_a.startswith("Bearer ") else f"Bearer {token_a}"}
    headers_b = {"Authorization": token_b if token_b.startswith("Bearer ") else f"Bearer {token_b}"}

    # Setup Audit Logging
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_log_file = out_dir / "scan_audit.log"
    
    def audit_log(phase: str, method: str, url: str, status: int, skipped: bool):
        import datetime
        try:
            entry = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "phase": phase,
                "method": method.upper(),
                "url": url,
                "status_code": status,
                "skipped": skipped
            }
            with open(audit_log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    # 2. OpenAPI Seeding (User A)
    console.print("[bold blue][1/3] Harvesting resources and computing baseline volatility as User A...[/bold blue]")
    seeder = OpenAPISeeder(base_url=base_url, user_a_headers=headers_a, audit_log=audit_log)
    seed_result = seeder.seed_endpoints(paths)

    console.print(f"Discovered [bold green]{len(seed_result.resources)}[/bold green] baseline resource combinations.")
    if verbose:
        for w in seed_result.warnings:
            console.print(f"[dim yellow]Warning: {w}[/dim yellow]")

    if not seed_result.resources:
        console.print("[bold yellow]No valid resource seeds could be fetched. Exiting scan.[/bold yellow]")
        raise typer.Exit(code=0)

    # 3. Cross-Token Replay & Matrix Evaluation (User B)
    console.print("[bold blue][2/3] Replaying resource requests as User B (Attacker)...[/bold blue]")
    if rate_delay > 0:
        import time
        time.sleep(rate_delay)

    matrix_runner = BolaMatrixRunner(user_b_headers=headers_b, allow_destructive=allow_destructive, audit_log=audit_log)
    findings = matrix_runner.run(seed_result)

    # Display Findings Table
    table = Table(title="LeakRadar Vulnerability Summary", show_header=True, header_style="bold magenta")
    table.add_column("Endpoint", style="cyan")
    table.add_column("Params", style="dim")
    table.add_column("Status", justify="center")
    table.add_column("Overlap", justify="right")
    table.add_column("Confidence", justify="center")

    for f in findings:
        conf_style = "bold red" if f.confidence == "high" else "bold yellow"
        param_desc = json.dumps(f.seed.param_values)
        table.add_row(
            f.seed.endpoint_template,
            param_desc,
            str(f.probe_status_code),
            f"{f.overlap_score * 100:.1f}%",
            f"[{conf_style}]{f.confidence.upper()}[/{conf_style}]",
        )

    console.print(table)

    # 4. Report Generation
    console.print("[bold blue][3/3] Generating redacted proof-of-concept reports...[/bold blue]")
    os.makedirs(output, exist_ok=True)

    custom_tokens = [token_a, token_b]

    # Markdown Export
    if format_choice.lower() in ("markdown", "all", "pdf"):
        for f in findings:
            filename = _generate_collision_proof_filename(f)
            md_content = MarkdownPoCExporter.export(f, target_name=target_name, custom_tokens=custom_tokens)
            md_path = os.path.join(output, f"{filename}.md")
            with open(md_path, "w", encoding="utf-8") as file_out:
                file_out.write(md_content)
            console.print(f"Saved Markdown PoC: [bold green]{md_path}[/bold green]")

    # PDF Export
    if format_choice.lower() in ("pdf", "all"):
        if PDFReportGenerator is None:
            console.print("[bold red]PDF export requires Pro Auditor tier and the pdf_report extension.[/bold red]")
            if format_choice.lower() == "pdf":
                raise typer.Exit(code=1)
        else:
            pdf_path = os.path.join(output, "LeakRadar_Audit_Report.pdf")
            PDFReportGenerator.generate(
                findings=findings,
                target_name=target_name,
                output_path=pdf_path,
                client_name="Client Audit",
                custom_tokens=custom_tokens,
                company_name=company,
                logo_path=logo,
            )
            console.print(f"Saved Executive PDF Report: [bold green]{pdf_path}[/bold green]")

    console.print(
        Panel.fit(
            f"[bold green]Scan Completed Successfully![/bold green]\n"
            f"Total Findings: [bold]{len(findings)}[/bold]\n"
            f"Output Directory: [bold]{output}[/bold]",
            title="Scan Finished",
        )
    )


def interactive_menu():
    """
    Interactive terminal menu displayed when leakradar.exe is double-clicked in Windows Explorer or launched without arguments.
    Runs continuously in a loop until the user chooses option 4 to exit.
    """
    while True:
        lic_ctx = LicenseManager.get_active_context()

        console.print(
            Panel.fit(
                f"[bold cyan]LeakRadar API Security Scanner v{__version__}[/bold cyan]\n"
                f"[dim]Autonomous BOLA / IDOR Vulnerability Detection Engine[/dim]\n"
                f"License Status: {'[bold green]ACTIVE (' + lic_ctx.tier.upper() + ')[/bold green]' if lic_ctx.active else '[bold yellow]COMMUNITY EDITION (FREE)[/bold yellow]'}",
                title="Welcome to LeakRadar",
            )
        )

        console.print("\n[bold]Select an action:[/bold]")
        console.print("  [cyan]1[/cyan] Run BOLA Vulnerability Scan")
        console.print("  [cyan]2[/cyan] Activate License Key (auth)")
        console.print("  [cyan]3[/cyan] View Command Help")
        console.print("  [cyan]4[/cyan] Exit")

        choice = input("\nEnter option (1-4) [1]: ").strip() or "1"

        if choice == "1":
            console.print("\n[bold blue]--- Interactive Scan Setup ---[/bold blue]")
            base_url = input("Target Base URL (e.g., http://localhost:5000): ").strip()
            if not base_url:
                console.print("[red]Base URL is required.[/red]")
                input("\nPress Enter to return to main menu...")
                continue

            specs_dir = Path(__file__).parent / "specs"
            default_std_spec = str(specs_dir / "standard_demo_spec.json")
            default_pro_spec = str(specs_dir / "pro_enterprise_spec.json")

            console.print("\n[dim]Choose an OpenAPI spec path/URL, or press Enter for default bundled benchmark:[/dim]")
            if lic_ctx.active:
                console.print(f"  [cyan]1[/cyan] Bundled Pro Enterprise Suite ({default_pro_spec})")
                console.print(f"  [cyan]2[/cyan] Bundled Standard Benchmark ({default_std_spec})")
                console.print(f"  [cyan]3[/cyan] Custom file path or HTTP URL")
                spec_choice = input("Enter choice (1-3) [1]: ").strip() or "1"
                if spec_choice == "1":
                    spec = default_pro_spec
                elif spec_choice == "2":
                    spec = default_std_spec
                else:
                    spec = input("Enter custom OpenAPI Spec path/URL: ").strip()
            else:
                console.print(f"  [cyan]1[/cyan] Bundled Standard Benchmark ({default_std_spec})")
                console.print("  [cyan]2[/cyan] Custom file path or HTTP URL")
                spec_choice = input("Enter choice (1-2) [1]: ").strip() or "1"
                if spec_choice == "1":
                    spec = default_std_spec
                else:
                    spec = input("Enter custom OpenAPI Spec path/URL: ").strip()

            if not spec:
                console.print("[red]OpenAPI Spec is required.[/red]")
                input("\nPress Enter to return to main menu...")
                continue

            token_a = input("User A Authorization Header / Token (Victim): ").strip()
            if not token_a:
                console.print("[red]Token A is required.[/red]")
                input("\nPress Enter to return to main menu...")
                continue

            token_b = input("User B Authorization Header / Token (Attacker): ").strip()
            if not token_b:
                console.print("[red]Token B is required.[/red]")
                input("\nPress Enter to return to main menu...")
                continue

            fmt = input("Report Format (markdown, pdf, all) [all]: ").strip() or "all"
            allow_dest = input("Allow Destructive Probing (POST/PUT/DELETE)? (y/N) [N]: ").strip().lower() in ("y", "yes")

            try:
                scan_command(
                    base_url=base_url,
                    spec=spec,
                    token_a=token_a,
                    token_b=token_b,
                    output="./findings",
                    format_choice=fmt,
                    allow_destructive=allow_dest,
                )
            except SystemExit:
                pass
            except Exception as e:
                console.print(f"[bold red]Scan error:[/bold red] {e}")

            input("\nPress Enter to return to main menu...")

        elif choice == "2":
            console.print("\n[bold blue]--- License Activation ---[/bold blue]")
            key = input("Enter Dodo Payments License Key: ").strip()
            if key:
                try:
                    auth_command(key=key)
                except Exception as e:
                    console.print(f"[bold red]Activation error:[/bold red] {e}")
            else:
                console.print("[yellow]No license key entered.[/yellow]")

            input("\nPress Enter to return to main menu...")

        elif choice == "3":
            try:
                app(["--help"])
            except SystemExit:
                pass

            input("\nPress Enter to return to main menu...")

        elif choice == "4":
            console.print("\n[dim]Exiting LeakRadar. Goodbye![/dim]")
            break


if __name__ == "__main__":
    if len(sys.argv) == 1:
        interactive_menu()
    else:
        app()

