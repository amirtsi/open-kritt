import threading
from contextlib import contextmanager
from types import SimpleNamespace

import psycopg

from open_kritt_engine import worker as worker_module
from open_kritt_engine.models import ModelSelection
from open_kritt_engine.worker import DatabaseUnavailable, Worker


class _Connection:
    def commit(self):
        return None


class _OutageDatabase:
    """A database that refuses the first `down_for` connections, like Postgres while it restarts."""

    def __init__(self, *, down_for=0):
        self.down_for = down_for
        self.scan = {"id": 27, "workflow_id": 28, "status": "running", "repo_full": "owner/repo", "harness": "codex"}
        self.statuses = []
        self.metadata_updates = []

    @contextmanager
    def connect(self):
        if self.down_for > 0:
            self.down_for -= 1
            raise psycopg.OperationalError("the database system is starting up")
        yield _Connection()

    def claim_scan(self, _conn):
        return dict(self.scan)

    def set_scan_status_if_active(self, _conn, scan_id, status, error=None):
        self.statuses.append((scan_id, status, error))
        self.scan["status"] = status

    def update_metadata(self, _conn, metadata_id, **fields):
        self.metadata_updates.append((metadata_id, fields))


def _worker(db, monkeypatch):
    worker = Worker.__new__(Worker)
    worker.db = db
    worker.config = SimpleNamespace(harness_timeout_seconds=1, codex_model_provider=None, data_dir="/tmp/unused")
    worker.codex_cli_gate = None
    worker.runtime_worker_count = lambda: 2
    worker._schedule_post_task_cleanup = lambda: None
    monkeypatch.setattr(worker_module.time, "sleep", lambda _seconds: None)
    return worker


def _raise(exc):
    def run(*_args, **_kwargs):
        raise exc

    return run


def test_database_outage_during_a_job_keeps_the_scan_and_requeues_the_job(monkeypatch):
    db = _OutageDatabase()
    worker = _worker(db, monkeypatch)
    worker.process_scan = _raise(DatabaseUnavailable("the database system is starting up", metadata_id=10857))
    db.down_for = 0
    original = worker.process_scan

    def process_scan(*args, **kwargs):
        db.down_for = 3  # still restarting for the next three connection attempts
        return original(*args, **kwargs)

    worker.process_scan = process_scan

    assert worker.run_scan_once(worker_id=2) is True

    assert db.statuses == []
    assert db.scan["status"] == "running"
    assert len(db.metadata_updates) == 1
    metadata_id, fields = db.metadata_updates[0]
    assert metadata_id == 10857
    assert fields["status"] == "stopped"
    assert fields["phase"] == "interrupted"


def test_database_outage_outside_a_job_keeps_the_scan(monkeypatch):
    db = _OutageDatabase()
    worker = _worker(db, monkeypatch)
    worker.process_scan = _raise(psycopg.OperationalError("failed to resolve host 'db'"))

    assert worker.run_scan_once(worker_id=2) is True

    assert db.statuses == []
    assert db.metadata_updates == []


def test_other_errors_still_fail_the_scan(monkeypatch):
    db = _OutageDatabase()
    worker = _worker(db, monkeypatch)
    worker.process_scan = _raise(RuntimeError("workflow is broken"))

    assert worker.run_scan_once(worker_id=2) is True

    assert db.statuses == [(27, "failed", "workflow is broken")]


class _JobDatabase(_OutageDatabase):
    def load_scan(self, _conn, _scan_id):
        return dict(self.scan)

    def claim_step_metadata(self, _conn, **_fields):
        return 10857

    def load_agent_skills(self, _conn, _scan):
        self.down_for = 5  # the database goes away while the job is being set up
        raise psycopg.OperationalError("server closed the connection unexpectedly")


def test_a_job_that_loses_the_database_reports_its_metadata_id(monkeypatch):
    db = _JobDatabase()
    worker = _worker(db, monkeypatch)
    worker.workspace_setup_slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(worker_module, "cleanup_job_workspace", lambda *_args: None)
    job = SimpleNamespace(
        step=SimpleNamespace(id=1, depth=1, output_format={}, multi_output=False, content=""),
        state=SimpleNamespace(prev_id=None, prev_table=None, repeat_run=1),
    )
    selection = ModelSelection(model="gpt-6-sol", model_provider="codex", harness="codex", thinking_effort="high")

    try:
        worker.execute_job(scan=db.scan, workflow_id=28, job=job, harness=object(), model_selection=selection)
    except DatabaseUnavailable as exc:
        assert exc.metadata_id == 10857
    else:
        raise AssertionError("expected DatabaseUnavailable")
