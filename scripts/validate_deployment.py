#!/usr/bin/env python3
"""Pre-deployment validation script for AETHER backend.

Run this before deploying to verify configuration is correct.
Usage: python scripts/validate_deployment.py
"""

import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


def check(name: str, condition: bool, detail: str = ""):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" - {detail}" if detail else ""))
    return condition


def main():
    print("AETHER Pre-Deployment Validation\n" + "=" * 40)
    errors = 0

    # Backend files
    print("\n1. Backend Files")
    errors += not check("backend/Dockerfile", (BACKEND_DIR / "Dockerfile").exists())
    errors += not check("backend/requirements.txt", (BACKEND_DIR / "requirements.txt").exists())
    errors += not check("backend/start.sh", (BACKEND_DIR / "start.sh").exists())
    errors += not check("backend/alembic.ini", (BACKEND_DIR / "alembic.ini").exists())
    errors += not check("backend/alembic/env.py", (BACKEND_DIR / "alembic" / "env.py").exists())
    errors += not check("backend/alembic/versions/001_initial_schema.py", (BACKEND_DIR / "alembic" / "versions" / "001_initial_schema.py").exists())
    errors += not check("backend/alembic/versions/002_add_git_target_columns.py", (BACKEND_DIR / "alembic" / "versions" / "002_add_git_target_columns.py").exists())
    errors += not check("backend/app/api/main.py", (BACKEND_DIR / "app" / "api" / "main.py").exists())

    # Frontend files
    print("\n2. Frontend Files")
    errors += not check("frontend/Dockerfile", (FRONTEND_DIR / "Dockerfile").exists())
    errors += not check("frontend/package.json", (FRONTEND_DIR / "package.json").exists())
    errors += not check("frontend/nginx.conf", (FRONTEND_DIR / "nginx.conf").exists())

    # Fly.io config
    print("\n3. Fly.io Configuration")
    fly_toml = Path(__file__).resolve().parents[1] / "fly.toml"
    errors += not check("fly.toml exists", fly_toml.exists())
    if fly_toml.exists():
        content = fly_toml.read_text()
        errors += not check("app name defined", "app = " in content)
        errors += not check("health check path", "/health" in content)
        errors += not check("release_command defined", "release_command" in content)
        errors += not check("alembic in release_command", "alembic" in content)

    # Environment variables
    print("\n4. Environment Variables (from .env)")
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    errors += not check("DATABASE_URL set", bool(os.getenv("DATABASE_URL")))
    errors += not check("AETHER_JWT_SECRET set", bool(os.getenv("AETHER_JWT_SECRET")))

    # Python imports
    print("\n5. Python Import Check")
    sys.path.insert(0, str(BACKEND_DIR))
    try:
        from app.api.main import app
        errors += not check("FastAPI app imports", True)
    except Exception as e:
        errors += not check("FastAPI app imports", False, str(e))

    try:
        from app.services.storage import ScanStorage
        errors += not check("ScanStorage imports", True)
    except Exception as e:
        errors += not check("ScanStorage imports", False, str(e))

    # Summary
    print("\n" + "=" * 40)
    if errors == 0:
        print("ALL CHECKS PASSED - Ready for deployment")
    else:
        print(f"{errors} CHECK(S) FAILED - Fix issues before deploying")
    return errors


if __name__ == "__main__":
    sys.exit(main())
