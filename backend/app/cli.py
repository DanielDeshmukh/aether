"""AETHER CLI - Unified command-line interface for the AETHER security platform."""

import os
import sys
import signal
import shutil
import subprocess
import time
import json
import threading
from pathlib import Path
from typing import Any, Optional

import click

# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if attr.isupper() and attr != "RESET":
                setattr(cls, attr, "")

# Detect no-color flag
if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
    Colors.disable()


def banner():
    """Print the AETHER CLI banner."""
    click.echo(f"""
{Colors.CYAN}{Colors.BOLD}    _   ____  _____ _   _ _____ ____ _____ ___  _   _
   / \\ |  _ \\| ____| \\ | |_   _|  _ \\_   _/ _ \\| \\ | |
  / _ \\| |_) |  _| |  \\| | | | | | | | || | | |  \\| |
 / ___ \\  __/| |___| |\\  | | | | |_| | || |_| | |\\  |
/_/   \\_\\____|_____|_| \\_| |_| |____/ |_| \\___/|_| \\_|{Colors.RESET}
{Colors.DIM}    Security Intelligence Platform - CLI v1.0.0{Colors.RESET}
""")


def log_info(msg: str):
    click.echo(f"{Colors.GREEN}{'[info]':<8}{Colors.RESET} {msg}")

def log_warn(msg: str):
    click.echo(f"{Colors.YELLOW}{'[warn]':<8}{Colors.RESET} {msg}")

def log_error(msg: str):
    click.echo(f"{Colors.RED}{'[error]':<8}{Colors.RESET} {msg}", err=True)

def log_service(name: str, msg: str, color: str = Colors.CYAN):
    click.echo(f"{color}{Colors.BOLD}[{name}]{Colors.RESET} {msg}")


# ─── Process Management ───────────────────────────────────────────────

class ProcessManager:
    """Manages child processes with graceful shutdown."""

    def __init__(self):
        self.processes: dict[str, subprocess.Popen] = {}
        self._shutdown_event = threading.Event()
        self._original_sigint = signal.getsignal(signal.SIGINT)
        self._original_sigterm = signal.getsignal(signal.SIGTERM)

    def register(self, name: str, proc: subprocess.Popen):
        self.processes[name] = proc

    def shutdown_all(self):
        """Gracefully shutdown all processes."""
        if self._shutdown_event.is_set():
            return
        self._shutdown_event.set()

        click.echo()
        log_info("Shutting down services...")

        # Terminate in reverse order
        for name, proc in reversed(list(self.processes.items())):
            if proc.poll() is None:
                log_info(f"Stopping {name} (PID {proc.pid})...")
                try:
                    proc.terminate()
                except OSError:
                    pass

        # Wait for graceful shutdown (5s timeout)
        deadline = time.time() + 5
        for name, proc in self.processes.items():
            remaining = max(0, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
                log_info(f"{name} stopped gracefully")
            except subprocess.TimeoutExpired:
                log_warn(f"Force killing {name}...")
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except OSError:
                    pass

        log_info("All services stopped")
        click.echo(f"{Colors.GREEN}{Colors.BOLD}Goodbye! 👋{Colors.RESET}")

    def _signal_handler(self, signum, frame):
        self.shutdown_all()
        sys.exit(0)

    def install_signal_handlers(self):
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)


# ─── Environment Validation ──────────────────────────────────────────

def validate_env(strict: bool = True) -> bool:
    """Validate environment configuration."""
    from dotenv import load_dotenv
    load_dotenv()

    required_vars = ["AETHER_JWT_SECRET", "DATABASE_URL", "FRONTEND_URL"]
    placeholder_patterns = ["your_", "example", "changeme"]
    missing = []
    placeholders = []

    for var in required_vars:
        value = os.environ.get(var, "").strip()
        if not value:
            missing.append(var)
        elif any(p in value.lower() for p in placeholder_patterns):
            placeholders.append(var)

    if missing:
        log_error(f"Missing required env vars: {', '.join(missing)}")
        log_error("Copy .env.example to .env and fill in the values")
        return False

    if placeholders and strict:
        log_error(f"Placeholder values detected: {', '.join(placeholders)}")
        log_error("Replace placeholder values with real credentials")
        return False

    return True


def check_port(port: int) -> bool:
    """Check if a port is available."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def wait_for_port(port: int, timeout: float = 30.0) -> bool:
    """Wait for a port to become available."""
    import socket
    start = time.time()
    while time.time() - start < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.3)
    return False


# ─── CLI Group ────────────────────────────────────────────────────────

@click.group()
@click.version_option(version="1.0.0", prog_name="aether")
def cli():
    """AETHER Security Platform - CLI Management Tool

    Start services, run migrations, and manage the AETHER platform
    from a single command-line interface.

    \b
    Quick Start:
      aether run          Start all services (backend + frontend)
      aether dev          Start in development mode (hot reload)
      aether status       Check service health
    """
    pass


# ─── aether run ───────────────────────────────────────────────────────

@cli.command()
@click.option("--backend-port", "-b", default=8000, help="Backend port", type=int)
@click.option("--frontend-port", "-f", default=5173, help="Frontend port", type=int)
@click.option("--no-frontend", is_flag=True, help="Skip frontend service")
@click.option("--no-env-check", is_flag=True, help="Skip environment validation")
@click.option("--production", "-p", is_flag=True, help="Run in production mode")
def run(backend_port: int, frontend_port: int, no_frontend: bool, no_env_check: bool, production: bool):
    """Start all AETHER services.

    Launches the backend API server and frontend dev server with
    graceful shutdown on Ctrl+C.

    \b
    Examples:
      aether run                    # Start everything
      aether run -b 9000 -f 3000   # Custom ports
      aether run --no-frontend      # Backend only
      aether run -p                 # Production mode
    """
    banner()

    root_dir = Path(__file__).parent.parent.parent
    backend_dir = root_dir / "backend"
    frontend_dir = root_dir / "frontend"

    # Validate environment
    if not no_env_check:
        log_info("Validating environment...")
        if not validate_env(strict=not production):
            sys.exit(1)
        log_info("Environment OK")
    else:
        log_warn("Skipping environment validation")

    # Check ports
    if not check_port(backend_port):
        log_error(f"Port {backend_port} is already in use")
        log_error(f"Try: aether run -b {backend_port + 1}")
        sys.exit(1)

    if not no_frontend and not check_port(frontend_port):
        log_error(f"Port {frontend_port} is already in use")
        log_error(f"Try: aether run -f {frontend_port + 1}")
        sys.exit(1)

    manager = ProcessManager()
    manager.install_signal_handlers()

    mode = "production" if production else "development"
    log_info(f"Starting AETHER in {Colors.BOLD}{mode}{Colors.RESET} mode")
    click.echo()

    try:
        # Start backend
        backend_cmd = [
            sys.executable, "-m", "uvicorn",
            "app.api.main:app",
            "--host", "0.0.0.0",
            "--port", str(backend_port),
        ]
        if not production:
            backend_cmd.append("--reload")

        log_info(f"Starting backend on port {backend_port}...")
        backend_proc = subprocess.Popen(
            backend_cmd,
            cwd=str(backend_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        manager.register("backend", backend_proc)

        # Stream backend output in a thread
        def stream_output(proc, name, color):
            for line in proc.stdout:
                log_service(name, line.rstrip(), color)

        backend_thread = threading.Thread(
            target=stream_output, args=(backend_proc, "backend", Colors.CYAN), daemon=True
        )
        backend_thread.start()

        # Wait for backend to be ready
        log_info("Waiting for backend to be ready...")
        if wait_for_port(backend_port, timeout=30):
            log_info(f"Backend is ready on {Colors.GREEN}http://localhost:{backend_port}{Colors.RESET}")
        else:
            log_warn("Backend may not be fully ready yet")

        # Start frontend
        if not no_frontend and frontend_dir.exists():
            click.echo()
            log_info(f"Starting frontend on port {frontend_port}...")

            frontend_env = os.environ.copy()
            frontend_env["VITE_API_URL"] = f"http://localhost:{backend_port}"

            npm_path = shutil.which("npm")
            if not npm_path:
                log_warn("npm not found in PATH. Skipping frontend.")
                return
            frontend_cmd = [npm_path, "run", "dev", "--", "--port", str(frontend_port)]

            frontend_proc = subprocess.Popen(
                frontend_cmd,
                cwd=str(frontend_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=frontend_env,
            )
            manager.register("frontend", frontend_proc)

            frontend_thread = threading.Thread(
                target=stream_output, args=(frontend_proc, "frontend", Colors.MAGENTA), daemon=True
            )
            frontend_thread.start()

            if wait_for_port(frontend_port, timeout=30):
                log_info(f"Frontend is ready on {Colors.GREEN}http://localhost:{frontend_port}{Colors.RESET}")
            else:
                log_warn("Frontend may not be fully ready yet")

        click.echo()
        click.echo(f"{Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════════════════╗{Colors.RESET}")
        click.echo(f"{Colors.GREEN}{Colors.BOLD}║         AETHER is running!                       ║{Colors.RESET}")
        click.echo(f"{Colors.GREEN}{Colors.BOLD}╠══════════════════════════════════════════════════╣{Colors.RESET}")
        click.echo(f"{Colors.GREEN}{Colors.BOLD}║  Backend API:   http://localhost:{backend_port:<5}            ║{Colors.RESET}")
        if not no_frontend:
            click.echo(f"{Colors.GREEN}{Colors.BOLD}║  Frontend:      http://localhost:{frontend_port:<5}            ║{Colors.RESET}")
            click.echo(f"{Colors.GREEN}{Colors.BOLD}║  API Proxy:     /api → localhost:{backend_port}          ║{Colors.RESET}")
        click.echo(f"{Colors.GREEN}{Colors.BOLD}║  Press Ctrl+C to stop                             ║{Colors.RESET}")
        click.echo(f"{Colors.GREEN}{Colors.BOLD}╚══════════════════════════════════════════════════╝{Colors.RESET}")
        click.echo()

        # Keep main thread alive
        while not manager._shutdown_event.is_set():
            time.sleep(1)

    except KeyboardInterrupt:
        manager.shutdown_all()


# ─── aether dev ───────────────────────────────────────────────────────

@cli.command()
@click.option("--backend-port", "-b", default=8000, help="Backend port", type=int)
@click.option("--frontend-port", "-f", default=5173, help="Frontend port", type=int)
@click.option("--no-frontend", is_flag=True, help="Skip frontend service")
def dev(backend_port: int, frontend_port: int, no_frontend: bool):
    """Start in development mode with hot reload.

    Convenience alias for `aether run` with development defaults.
    Backend uses --reload for automatic restarts on code changes.
    """
    # Invoke run with dev defaults
    ctx = click.get_current_context()
    ctx.invoke(run,
               backend_port=backend_port,
               frontend_port=frontend_port,
               no_frontend=no_frontend,
               no_env_check=False,
               production=False)


# ─── aether build ─────────────────────────────────────────────────────

@cli.command()
@click.option("--clean", is_flag=True, help="Clean build artifacts first")
def build(clean: bool):
    """Build frontend for production.

    Compiles the React frontend into optimized static assets
    served by nginx in production.
    """
    banner()

    import shutil

    root_dir = Path(__file__).parent.parent.parent
    frontend_dir = root_dir / "frontend"

    if not frontend_dir.exists():
        log_error("Frontend directory not found")
        sys.exit(1)

    if clean:
        log_info("Cleaning build artifacts...")
        dist_dir = frontend_dir / "dist"
        if dist_dir.exists():
            shutil.rmtree(dist_dir)
            log_info("Cleaned dist/")

        node_modules = frontend_dir / "node_modules"
        if node_modules.exists():
            shutil.rmtree(node_modules)
            log_info("Cleaned node_modules/")

    # Install dependencies
    npm_path = shutil.which("npm")
    if not npm_path:
        log_error("npm not found in PATH. Cannot build frontend.")
        sys.exit(1)

    log_info("Installing frontend dependencies...")
    result = subprocess.run(
        [npm_path, "install"],
        cwd=str(frontend_dir),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log_error(f"npm install failed:\n{result.stderr}")
        sys.exit(1)
    log_info("Dependencies installed")

    # Build
    log_info("Building frontend...")
    result = subprocess.run(
        [npm_path, "run", "build"],
        cwd=str(frontend_dir),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log_error(f"Build failed:\n{result.stderr}")
        sys.exit(1)

    click.echo(f"\n{Colors.GREEN}{Colors.BOLD}Build successful!{Colors.RESET}")
    click.echo(f"Output: {frontend_dir / 'dist'}")


# ─── aether test ──────────────────────────────────────────────────────

@cli.command()
@click.option("--coverage", "-c", is_flag=True, help="Run with coverage report")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--filter", "-k", help="Filter tests by name pattern")
def test(coverage: bool, verbose: bool, filter: Optional[str]):
    """Run backend test suite.

    Executes pytest with optional coverage reporting.

    \b
    Examples:
      aether test                # Run all tests
      aether test -c             # With coverage
      aether test -k test_auth   # Only auth tests
      aether test -v             # Verbose output
    """
    banner()

    root_dir = Path(__file__).parent.parent.parent
    backend_dir = root_dir / "backend"

    cmd = [sys.executable, "-m", "pytest"]

    if verbose:
        cmd.append("-v")

    if filter:
        cmd.extend(["-k", filter])

    if coverage:
        cmd.extend(["--cov=app", "--cov-report=term-missing", "--cov-report=html"])

    log_info("Running test suite...")
    click.echo()

    result = subprocess.run(cmd, cwd=str(backend_dir))
    sys.exit(result.returncode)


# ─── aether db ────────────────────────────────────────────────────────

@cli.group()
def db():
    """Database management commands.

    Run migrations, seed data, and manage the database.
    """
    pass


@db.command("migrate")
@click.option("--revision", "-r", default="head", help="Target revision (default: head)")
def db_migrate(revision: str):
    """Run database migrations.

    \b
    Examples:
      aether db migrate          # Upgrade to latest
      aether db migrate -r abc123  # Upgrade to specific revision
    """
    root_dir = Path(__file__).parent.parent.parent
    backend_dir = root_dir / "backend"

    log_info(f"Running migrations to revision: {revision}")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", revision],
        cwd=str(backend_dir),
    )
    if result.returncode == 0:
        log_info("Migrations complete")
    else:
        log_error("Migration failed")
        sys.exit(1)


@db.command("downgrade")
@click.argument("revision")
def db_downgrade(revision: str):
    """Downgrade database to a specific revision.

    \b
    Example:
      aether db downgrade -1       # Go back one revision
      aether db downgrade abc123   # Go to specific revision
    """
    root_dir = Path(__file__).parent.parent.parent
    backend_dir = root_dir / "backend"

    log_warn(f"Downgrading to revision: {revision}")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", revision],
        cwd=str(backend_dir),
    )
    if result.returncode == 0:
        log_info("Downgrade complete")
    else:
        log_error("Downgrade failed")
        sys.exit(1)


@db.command("reset")
@click.confirmation_option(prompt="This will DROP all tables. Are you sure?")
def db_reset():
    """Reset database (drop all tables and re-migrate).

    WARNING: This destroys all data!
    """
    root_dir = Path(__file__).parent.parent.parent
    backend_dir = root_dir / "backend"

    log_warn("Resetting database...")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", "base"],
        cwd=str(backend_dir),
    )
    if result.returncode != 0:
        log_error("Failed to reset database")
        sys.exit(1)

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(backend_dir),
    )
    if result.returncode == 0:
        log_info("Database reset complete")
    else:
        log_error("Failed to re-run migrations")
        sys.exit(1)


@db.command("status")
def db_status():
    """Show current migration status."""
    root_dir = Path(__file__).parent.parent.parent
    backend_dir = root_dir / "backend"

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "current"],
        cwd=str(backend_dir),
    )
    sys.exit(result.returncode)


@db.command("history")
@click.option("--verbose", "-v", is_flag=True, help="Show full migration paths")
def db_history(verbose: bool):
    """Show migration history."""
    root_dir = Path(__file__).parent.parent.parent
    backend_dir = root_dir / "backend"

    cmd = [sys.executable, "-m", "alembic", "history"]
    if verbose:
        cmd.append("--verbose")

    result = subprocess.run(cmd, cwd=str(backend_dir))
    sys.exit(result.returncode)


# ─── aether status ────────────────────────────────────────────────────

@cli.command()
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def status(json_output: bool):
    """Check health of all AETHER services.

    Pings each service and reports its status.

    \b
    Examples:
      aether status          # Human-readable output
      aether status -j       # JSON output
    """
    import urllib.request
    import urllib.error

    services: dict[str, Any] = {
        "backend": {"url": "http://localhost:8000/health", "port": 8000},
        "frontend": {"url": "http://localhost:5173", "port": 5173},
        "postgres": {"port": 5432},
        "redis": {"port": 6379},
    }

    results = {}
    all_healthy = True

    for name, info in services.items():
        status_str = "unknown"
        details = ""

        if "url" in info:
            try:
                req = urllib.request.Request(info["url"], method="GET")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        status_str = "healthy"
                        try:
                            data = json.loads(resp.read())
                            details = data.get("status", "")
                        except (json.JSONDecodeError, ValueError):
                            pass
                    else:
                        status_str = "unhealthy"
                        all_healthy = False
            except (urllib.error.URLError, OSError, ValueError):
                status_str = "offline"
                all_healthy = False
        else:
            # Check port only
            if check_port(info["port"]):
                status_str = "offline"
                all_healthy = False
            else:
                status_str = "in-use"
                details = "port occupied"

        results[name] = {"status": status_str, "details": details}

    if json_output:
        click.echo(json.dumps(results, indent=2))
    else:
        banner()
        click.echo(f"{Colors.BOLD}Service Status:{Colors.RESET}\n")

        for name, result in results.items():
            s = result["status"]
            detail_val = result["details"]
            if s == "healthy":
                icon = f"{Colors.GREEN}[OK]{Colors.RESET}"
                label = f"{Colors.GREEN}healthy{Colors.RESET}"
            elif s in ("offline", "unhealthy"):
                icon = f"{Colors.RED}[!!]{Colors.RESET}"
                label = f"{Colors.RED}{s}{Colors.RESET}"
            else:
                icon = f"{Colors.YELLOW}[--]{Colors.RESET}"
                label = f"{Colors.YELLOW}{s}{Colors.RESET}"

            details = f" ({detail_val})" if detail_val else ""
            click.echo(f"  {icon} {Colors.BOLD}{name:<12}{Colors.RESET} {label}{details}")

        click.echo()

        if all_healthy:
            click.echo(f"{Colors.GREEN}{Colors.BOLD}All services are healthy!{Colors.RESET}")
        else:
            click.echo(f"{Colors.YELLOW}Some services are not running.{Colors.RESET}")
            click.echo(f"{Colors.DIM}Run `aether run` to start them.{Colors.RESET}")


# ─── aether logs ──────────────────────────────────────────────────────

@cli.command()
@click.option("--service", "-s", type=click.Choice(["backend", "frontend", "all"]), default="all")
@click.option("--follow", "-f", is_flag=True, help="Follow log output")
@click.option("--lines", "-n", default=100, help="Number of lines to show")
def logs(service: str, follow: bool, lines: int):
    """View service logs.

    \b
    Examples:
      aether logs              # Show all recent logs
      aether logs -s backend   # Backend logs only
      aether logs -f           # Follow logs (tail -f)
    """
    root_dir = Path(__file__).parent.parent.parent
    log_dir = root_dir / "logs"

    if not log_dir.exists():
        log_warn("No logs directory found. Logs are written to stdout when using `aether run`.")
        log_info("Tip: Run `aether run` to see live logs.")
        return

    log_files = {
        "backend": log_dir / "backend.log",
        "frontend": log_dir / "frontend.log",
    }

    targets = [service] if service != "all" else ["backend", "frontend"]

    for svc in targets:
        log_file = log_files.get(svc)
        if log_file and log_file.exists():
            click.echo(f"{Colors.BOLD}--- {svc} logs ---{Colors.RESET}")
            if follow:
                subprocess.run(["tail", "-f", "-n", str(lines), str(log_file)])
            else:
                subprocess.run(["tail", "-n", str(lines), str(log_file)])
        else:
            log_warn(f"No log file found for {svc}")


# ─── aether clean ─────────────────────────────────────────────────────

@cli.command()
@click.option("--all", "-a", is_flag=True, help="Clean everything including node_modules")
@click.confirmation_option(prompt="This will remove build artifacts. Continue?")
def clean(all: bool):
    """Clean build artifacts and caches.

    \b
    Examples:
      aether clean          # Clean build output only
      aether clean -a       # Clean everything (including node_modules)
    """
    import shutil

    banner()

    root_dir = Path(__file__).parent.parent.parent
    cleaned = []

    # Python caches
    for pattern in ["**/__pycache__", "**/*.pyc", "**/.pytest_cache", "**/htmlcov"]:
        for path in root_dir.glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
                cleaned.append(str(path.relative_to(root_dir)))

    # Frontend build
    dist_dir = root_dir / "frontend" / "dist"
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
        cleaned.append("frontend/dist")

    if all:
        for name in ["node_modules", ".vite"]:
            for path in root_dir.rglob(name):
                if path.is_dir():
                    shutil.rmtree(path)
                    cleaned.append(str(path.relative_to(root_dir)))

    if cleaned:
        log_info(f"Cleaned {len(cleaned)} items:")
        for item in cleaned:
            click.echo(f"  {Colors.DIM}• {item}{Colors.RESET}")
    else:
        log_info("Nothing to clean")


# ─── aether info ──────────────────────────────────────────────────────

@cli.command()
def info():
    """Show AETHER project information and configuration."""
    banner()

    root_dir = Path(__file__).parent.parent.parent

    click.echo(f"{Colors.BOLD}Project Info:{Colors.RESET}\n")
    click.echo(f"  Root:         {root_dir}")
    click.echo(f"  Backend:      {root_dir / 'backend'}")
    click.echo(f"  Frontend:     {root_dir / 'frontend'}")
    click.echo(f"  Python:       {sys.version.split()[0]}")

    # Check node
    try:
        result = subprocess.run(["node", "--version"], capture_output=True, text=True)
        click.echo(f"  Node.js:      {result.stdout.strip()}")
    except FileNotFoundError:
        click.echo(f"  Node.js:      {Colors.RED}not found{Colors.RESET}")

    click.echo()

    # Environment status
    click.echo(f"{Colors.BOLD}Environment:{Colors.RESET}\n")

    from dotenv import load_dotenv
    load_dotenv(root_dir / ".env")

    env_vars = {
        "DATABASE_URL": "Database",
        "AETHER_JWT_SECRET": "JWT Secret",
        "FRONTEND_URL": "Frontend URL",
        "ENVIRONMENT": "Environment",
        "NVIDIA_API_KEY": "NVIDIA NIM AI",
        "SMTP_HOST": "SMTP Host",
    }

    for var, label in env_vars.items():
        value = os.environ.get(var, "")
        if value:
            if "secret" in var.lower() or "key" in var.lower():
                display = f"{value[:4]}...{value[-4:]}" if len(value) > 8 else "****"
            elif var == "DATABASE_URL":
                # Mask password
                display = value.split("@")[-1] if "@" in value else value[:30]
            else:
                display = value[:50]
            click.echo(f"  {Colors.GREEN}[+]{Colors.RESET} {label:<16} {display}")
        else:
            click.echo(f"  {Colors.RED}[-]{Colors.RESET} {label:<16} {Colors.DIM}not set{Colors.RESET}")

    click.echo()


# ─── Entry Point ──────────────────────────────────────────────────────

def main():
    """Main entry point for the AETHER CLI."""
    cli()


if __name__ == "__main__":
    main()
