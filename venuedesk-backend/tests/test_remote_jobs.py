"""Backend tests for remote job dispatch, polling, and execution reporting."""
import base64
import json
from datetime import UTC, datetime, timedelta

from app.extensions import db
from app.models import DeviceJob, DeviceStatus, JobStatus, JobType, User, UserRole
from app.services.job_service import create_job
from tests.test_authenticated_communication import create_enrolled_device, sign_request


def ensure_admin(app) -> dict[str, str]:
    """Helper ensuring an admin user exists and returning Basic auth headers."""
    with app.app_context():
        user = User.query.filter_by(username="jobs_admin").first()
        if not user:
            user = User(username="jobs_admin", role=UserRole.INFRA_ADMIN)
            user.set_password("adminpass")
            db.session.add(user)
            db.session.commit()
    return {"Authorization": "Basic " + base64.b64encode(b"jobs_admin:adminpass").decode("ascii")}


def ensure_viewer(app) -> dict[str, str]:
    """Helper ensuring an infra viewer user exists and returning Basic auth headers."""
    with app.app_context():
        user = User.query.filter_by(username="jobs_viewer").first()
        if not user:
            user = User(username="jobs_viewer", role=UserRole.INFRA_VIEWER)
            user.set_password("viewerpass")
            db.session.add(user)
            db.session.commit()
    return {"Authorization": "Basic " + base64.b64encode(b"jobs_viewer:viewerpass").decode("ascii")}


def test_admin_create_job_allowlisted(client, app):
    """Test admin can dispatch allowlisted job types and query them."""
    dev_id, _ = create_enrolled_device(app, status=DeviceStatus.ACTIVE)

    headers = ensure_admin(app)
    payload = {
        "job_type": "REFRESH_INVENTORY",
        "payload": {},
        "expires_in_seconds": 1800,
    }
    resp = client.post(
        f"/api/v1/admin/devices/{dev_id}/jobs",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["status"] == "dispatched"
    assert data["job_type"] == "REFRESH_INVENTORY"
    assert data["job_status"] == "PENDING"
    job_id = data["job_id"]

    # Query jobs list via admin viewer endpoint
    viewer_headers = ensure_viewer(app)
    get_resp = client.get(f"/api/v1/admin/devices/{dev_id}/jobs", headers=viewer_headers)
    assert get_resp.status_code == 200
    jobs_data = get_resp.get_json()
    assert jobs_data["count"] == 1
    assert jobs_data["jobs"][0]["id"] == job_id


def test_admin_create_job_unallowlisted_rejected(client, app):
    """Test dispatching unallowlisted job type returns 400."""
    dev_id, _ = create_enrolled_device(app, status=DeviceStatus.ACTIVE)

    headers = ensure_admin(app)
    payload = {
        "job_type": "EXECUTE_ARBITRARY_BASH",
        "payload": {"cmd": "rm -rf /"},
    }
    resp = client.post(
        f"/api/v1/admin/devices/{dev_id}/jobs",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_job"


def test_admin_create_job_rbac_enforcement(client, app):
    """Test infra_viewer cannot dispatch jobs (requires infra_admin)."""
    dev_id, _ = create_enrolled_device(app, status=DeviceStatus.ACTIVE)

    viewer_headers = ensure_viewer(app)
    resp = client.post(
        f"/api/v1/admin/devices/{dev_id}/jobs",
        json={"job_type": "COLLECT_LOGS"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


def test_agent_poll_and_report_job_lifecycle(client, app):
    """Test agent polling pending jobs, heartbeat pending_jobs indicator, and reporting result."""
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.ACTIVE)

    with app.app_context():
        job = create_job(
            device_identifier=dev_id,
            job_type=JobType.COLLECT_LOGS,
            payload={"max_bytes": 1000},
            created_by="admin_test",
        )
        job_id = job.id

    # 1. Heartbeat should report pending_jobs: True
    hb_body = json.dumps({"agent_instance_id": "inst-1"}).encode()
    hb_headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", hb_body)
    hb_headers["Content-Type"] = "application/json"
    hb_resp = client.post("/api/v1/agents/heartbeat", data=hb_body, headers=hb_headers)
    assert hb_resp.status_code == 200
    assert hb_resp.get_json()["pending_jobs"] is True

    # 2. Agent polls pending jobs
    poll_headers = sign_request(dev_id, key, "GET", "/api/v1/agents/jobs", b"")
    poll_resp = client.get("/api/v1/agents/jobs", headers=poll_headers)
    assert poll_resp.status_code == 200
    jobs = poll_resp.get_json()["jobs"]
    assert len(jobs) == 1
    assert jobs[0]["id"] == job_id
    assert jobs[0]["job_type"] == "COLLECT_LOGS"

    # Poll endpoint transitions job to DISPATCHED, so second poll has 0 jobs
    poll2_headers = sign_request(dev_id, key, "POST", "/api/v1/agents/jobs/poll", b"")
    poll2_resp = client.post("/api/v1/agents/jobs/poll", headers=poll2_headers)
    assert poll2_resp.status_code == 200
    assert len(poll2_resp.get_json()["jobs"]) == 0

    # 3. Agent reports execution success result
    result_data = {
        "status": "SUCCEEDED",
        "result": {"log_content": "everything normal", "size_bytes": 17},
        "error": None,
    }
    res_body = json.dumps(result_data).encode()
    res_headers = sign_request(
        dev_id, key, "POST", f"/api/v1/agents/jobs/{job_id}/result", res_body
    )
    res_headers["Content-Type"] = "application/json"
    res_resp = client.post(
        f"/api/v1/agents/jobs/{job_id}/result",
        data=res_body,
        headers=res_headers,
    )
    assert res_resp.status_code == 200
    assert res_resp.get_json()["status"] == "recorded"

    # Verify job status in database
    with app.app_context():
        updated_job = db.session.get(DeviceJob, job_id)
        assert updated_job.status == JobStatus.SUCCEEDED
        assert updated_job.completed_at is not None
        assert updated_job.result["result"]["size_bytes"] == 17

    # 4. Subsequent heartbeat (with fresh nonce) has pending_jobs: False
    hb2_headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", hb_body)
    hb2_headers["Content-Type"] = "application/json"
    hb2_resp = client.post("/api/v1/agents/heartbeat", data=hb_body, headers=hb2_headers)
    assert hb2_resp.status_code == 200
    assert hb2_resp.get_json()["pending_jobs"] is False


def test_expired_jobs_are_not_dispatched(client, app):
    """Test jobs past expires_at are marked EXPIRED and not returned in poll."""
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.ACTIVE)

    with app.app_context():
        # Create an already expired job
        job = create_job(
            device_identifier=dev_id,
            job_type=JobType.REFRESH_INVENTORY,
            expires_in_seconds=60,
        )
        job.expires_at = datetime.now(UTC) - timedelta(seconds=10)
        db.session.commit()
        job_id = job.id

    # Agent polls
    poll_headers = sign_request(dev_id, key, "GET", "/api/v1/agents/jobs", b"")
    poll_resp = client.get("/api/v1/agents/jobs", headers=poll_headers)
    assert poll_resp.status_code == 200
    assert len(poll_resp.get_json()["jobs"]) == 0

    with app.app_context():
        expired_job = db.session.get(DeviceJob, job_id)
        assert expired_job.status == JobStatus.EXPIRED
