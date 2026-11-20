from __future__ import annotations

import os
import re
import shutil
import subprocess
import time

import psycopg
import pytest

from src.security_engine.enforcement import NginxBlocklistManager
from src.security_engine.repository import SecurityRepository

TRUNCATE_SQL = "TRUNCATE events, alerts, ip_reputations, ip_reputation_transitions, audit_logs RESTART IDENTITY CASCADE"


def _wait_ready(url: str, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(url, connect_timeout=2) as conn:
                conn.execute("SELECT 1")
            return
        except Exception as exc:
            last_err = exc
            time.sleep(0.25)
    raise RuntimeError(f"Postgres did not become ready within {timeout_s}s: {last_err}")


def _assert_safe_test_db(url: str) -> None:
    """Refuse to run TRUNCATE against a non-test database unless explicitly opted in."""
    if os.getenv("ALLOW_TEST_DB_TRUNCATE") == "1":
        return
    with psycopg.connect(url, connect_timeout=2) as conn:
        row = conn.execute("SELECT current_database()").fetchone()
    db_name = row[0] if row else ""
    if not re.search(r"(?:^|[_-])test(?:$|[_-])", db_name, re.IGNORECASE):
        raise RuntimeError(
            f"Refusing to truncate database {db_name!r}: database name must contain a 'test' token "
            "or set ALLOW_TEST_DB_TRUNCATE=1."
        )


@pytest.fixture(scope="session")
def pg_url() -> str:
    env_url = os.getenv("TEST_DATABASE_URL")
    if env_url:
        _wait_ready(env_url)
        _assert_safe_test_db(env_url)
        yield env_url
        return

    docker = shutil.which("docker")
    if not docker:
        pytest.skip("Set TEST_DATABASE_URL or install Docker to run Postgres integration tests")

    probe = subprocess.run([docker, "info"], capture_output=True, text=True, check=False)  # noqa: S603
    if probe.returncode != 0:
        pytest.skip("Docker daemon unavailable and TEST_DATABASE_URL is not set")

    cid = ""
    try:
        run = subprocess.run(  # noqa: S603
            [
                docker,
                "run",
                "-d",
                "-p",
                "127.0.0.1:0:5432",
                "-e",
                "POSTGRES_USER=cybersiem",
                "-e",
                "POSTGRES_PASSWORD=cybersiem",
                "-e",
                "POSTGRES_DB=cybersiem_test",
                "postgres:16",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        cid = run.stdout.strip()
        port_out = subprocess.run(  # noqa: S603
            [docker, "port", cid, "5432/tcp"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        port = port_out.splitlines()[0].rsplit(":", 1)[1]
        url = f"postgresql://cybersiem:cybersiem@127.0.0.1:{port}/cybersiem_test"
        _wait_ready(url)
        yield url
    finally:
        if cid:
            subprocess.run([docker, "rm", "-f", cid], capture_output=True, check=False)  # noqa: S603


@pytest.fixture
def pg_repo(pg_url: str):
    repo = SecurityRepository(pg_url)
    try:
        repo.ensure_schema()
        with repo.connection() as conn:
            conn.execute(TRUNCATE_SQL)
            conn.commit()
        yield repo
    finally:
        repo.close()


@pytest.fixture
def blocklist_manager(tmp_path) -> NginxBlocklistManager:
    return NginxBlocklistManager(str(tmp_path / "blocklist.conf"))
