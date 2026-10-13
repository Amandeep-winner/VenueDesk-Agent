"""Comprehensive hardened security test suite for Phase 2.

Covers cryptographic verification, atomic replay protection, state policies,
token security, log redaction, and fail-closed endpoint coverage.
"""

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from test_authenticated_communication import create_enrolled_device, sign_request
from test_enrollment import create_test_endpoint_payload

from app import create_app
from app.extensions import db
from app.logging_filters import RedactingFilter
from app.models import (
    Asset,
    AssetDeviceLink,
    AuditLog,
    DeviceStatus,
    EnrollmentTokenStatus,
    PhysicalDevice,
    RelationshipStatus,
    generate_next_asset_id,
)
from app.security.policy import ENDPOINT_POLICY
from app.security.tokens import create_token_for_asset


def test_invalid_signature(app, client):
    """Requests signed with an incorrect or corrupted signature are rejected with generic 401 unauthorized."""
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.ACTIVE)
    body = b'{"ping": true}'
    headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", body)
    headers["X-Signature"] = "A" * 86 + "=="

    resp = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "unauthorized"


def test_tampered_body(app, client):
    """Tampering with body bytes after signature generation causes verification to fail."""
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.ACTIVE)
    original_body = b'{"status": "ok"}'
    tampered_body = b'{"status": "hacked"}'

    headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", original_body)
    resp = client.post("/api/v1/agents/heartbeat", data=tampered_body, headers=headers)
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "unauthorized"


def test_tampered_path_or_method(app, client):
    """Signatures computed for a different method or URL path cannot be reused."""
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.ACTIVE)
    body = b'{"data": "telemetry"}'

    # Signature signed for /api/v1/agents/telemetry
    headers = sign_request(dev_id, key, "POST", "/api/v1/agents/telemetry", body)

    # Replayed to /api/v1/agents/heartbeat
    resp = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "unauthorized"


def test_expired_timestamp(app, client):
    """Requests with timestamps older than allowable clock skew are rejected."""
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.ACTIVE)
    body = b"{}"
    headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", body, skew_seconds=-300)

    resp = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "unauthorized"


def test_future_timestamp(app, client):
    """Requests with timestamps in the future beyond allowable clock skew are rejected."""
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.ACTIVE)
    body = b"{}"
    headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", body, skew_seconds=300)

    resp = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "unauthorized"


def test_replayed_nonce(app, client):
    """A replayed nonce fails atomically and yields generic 401 unauthorized."""
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.ACTIVE)
    body = b"{}"
    fixed_nonce = uuid.uuid4().hex

    headers = sign_request(
        dev_id, key, "POST", "/api/v1/agents/heartbeat", body, override_nonce=fixed_nonce
    )
    r1 = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert r1.status_code == 200

    r2 = client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
    assert r2.status_code == 401
    assert r2.get_json()["error"] == "unauthorized"


def test_concurrent_same_nonce_exactly_one_wins(tmp_path):
    """Multiple threads sending requests with the exact same nonce results in exactly 1 success."""
    db_file = tmp_path / "nonce_concurrency.db"
    db_url = f"sqlite:///{db_file}"
    engine_opts = {"connect_args": {"timeout": 30}}

    init_app = create_app(
        "testing",
        test_config={"SQLALCHEMY_DATABASE_URI": db_url, "SQLALCHEMY_ENGINE_OPTIONS": engine_opts},
    )
    with init_app.app_context():
        with db.engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.commit()
        db.create_all()

    dev_id, key = create_enrolled_device(init_app, status=DeviceStatus.ACTIVE)
    fixed_nonce = uuid.uuid4().hex
    body = b'{"msg": "concurrent"}'
    headers = sign_request(
        dev_id, key, "POST", "/api/v1/agents/heartbeat", body, override_nonce=fixed_nonce
    )

    def send_req(_):
        worker_app = create_app(
            "testing",
            test_config={
                "SQLALCHEMY_DATABASE_URI": db_url,
                "SQLALCHEMY_ENGINE_OPTIONS": engine_opts,
            },
        )
        with worker_app.test_client() as worker_client:
            res = worker_client.post("/api/v1/agents/heartbeat", data=body, headers=headers)
            return res.status_code

    with ThreadPoolExecutor(max_workers=6) as executor:
        status_codes = list(executor.map(send_req, range(6)))

    assert status_codes.count(200) == 1
    assert status_codes.count(401) == 5


def test_revoked_device_telemetry_denied(app, client):
    """Revoked device is denied telemetry access with 403 device_blocked."""
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.REVOKED)
    body = b'{"events": []}'
    headers = sign_request(dev_id, key, "POST", "/api/v1/agents/telemetry", body)

    resp = client.post("/api/v1/agents/telemetry", data=body, headers=headers)
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "device_blocked"


def test_unclaimed_device_jobs_denied(app, client):
    """Unclaimed device is denied job polling with 403 device_blocked."""
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.UNCLAIMED)
    body = b""
    headers = sign_request(dev_id, key, "GET", "/api/v1/agents/jobs", body)

    resp = client.get("/api/v1/agents/jobs", headers=headers)
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "device_blocked"


def test_pending_device_cannot_send_telemetry(app, client):
    """Devices in PENDING_VERIFICATION or PENDING_REVERIFICATION cannot send telemetry."""
    for st in [DeviceStatus.PENDING_VERIFICATION, DeviceStatus.PENDING_REVERIFICATION]:
        dev_id, key = create_enrolled_device(app, status=st)
        body = b'{"metrics": []}'
        headers = sign_request(dev_id, key, "POST", "/api/v1/agents/telemetry", body)

        resp = client.post("/api/v1/agents/telemetry", data=body, headers=headers)
        assert resp.status_code == 403
        assert resp.get_json()["error"] == "device_blocked"


def test_suspended_device_denied_everything(app, client):
    """Suspended device is rejected on all endpoints."""
    dev_id, key = create_enrolled_device(app, status=DeviceStatus.SUSPENDED)

    # Heartbeat
    hb_body = b"{}"
    hb_headers = sign_request(dev_id, key, "POST", "/api/v1/agents/heartbeat", hb_body)
    assert (
        client.post("/api/v1/agents/heartbeat", data=hb_body, headers=hb_headers).status_code == 403
    )

    # Inventory
    inv_body = b'{"hostname": "test"}'
    inv_headers = sign_request(dev_id, key, "POST", "/api/v1/agents/inventory", inv_body)
    assert (
        client.post("/api/v1/agents/inventory", data=inv_body, headers=inv_headers).status_code
        == 403
    )

    # Telemetry
    tel_body = b'{"metrics": []}'
    tel_headers = sign_request(dev_id, key, "POST", "/api/v1/agents/telemetry", tel_body)
    assert (
        client.post("/api/v1/agents/telemetry", data=tel_body, headers=tel_headers).status_code
        == 403
    )

    # Jobs
    job_headers = sign_request(dev_id, key, "GET", "/api/v1/agents/jobs", b"")
    assert client.get("/api/v1/agents/jobs", headers=job_headers).status_code == 403


def test_expired_token(app, client):
    """Enrolling with an expired pairing token returns 400 invalid_enrollment_token."""
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="TEST-EXPIRED-TOK")
        db.session.add(asset)
        db.session.commit()

        raw_tok, tok_obj = create_token_for_asset(asset.id)
        tok_obj.expires_at = datetime.now(UTC) - timedelta(hours=2)
        db.session.commit()

    payload, _ = create_test_endpoint_payload(token=raw_tok)
    resp = client.post("/api/v1/agents/enroll", json=payload)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_enrollment_token"


def test_reused_token(app, client):
    """Enrolling with an already-used token is rejected with 400 invalid_enrollment_token."""
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="TEST-REUSED-TOK")
        db.session.add(asset)
        db.session.commit()

        raw_tok, _ = create_token_for_asset(asset.id)
        db.session.commit()

    # First enrollment succeeds
    payload1, _ = create_test_endpoint_payload(token=raw_tok, hardware_suffix="dev1")
    r1 = client.post("/api/v1/agents/enroll", json=payload1)
    assert r1.status_code == 200

    # Second enrollment fails
    payload2, _ = create_test_endpoint_payload(token=raw_tok, hardware_suffix="dev2")
    r2 = client.post("/api/v1/agents/enroll", json=payload2)
    assert r2.status_code == 400
    assert r2.get_json()["error"] == "invalid_enrollment_token"


def test_revoked_token(app, client):
    """Enrolling with a revoked token returns 400 invalid_enrollment_token."""
    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="TEST-REVOKED-TOK")
        db.session.add(asset)
        db.session.commit()

        raw_tok, tok_obj = create_token_for_asset(asset.id)
        tok_obj.status = EnrollmentTokenStatus.REVOKED
        tok_obj.revoked_at = datetime.now(UTC)
        db.session.commit()

    payload, _ = create_test_endpoint_payload(token=raw_tok)
    resp = client.post("/api/v1/agents/enroll", json=payload)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_enrollment_token"


def test_token_for_asset_a_cannot_enroll_as_asset_b(app, client):
    """Token scoped to Asset A pairs exclusively with Asset A and cannot link Asset B."""
    with app.app_context():
        asset_a = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="ASSET-A-101")
        asset_b = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="ASSET-B-102")
        db.session.add_all([asset_a, asset_b])
        db.session.commit()

        raw_token, _ = create_token_for_asset(asset_a.id)
        db.session.commit()
        asset_a_id = asset_a.id
        asset_b_id = asset_b.id
        asset_b_tag = asset_b.asset_id

    payload, _ = create_test_endpoint_payload(token=raw_token, hardware_suffix="scoped-dev")
    # Even if payload maliciously includes asset_b identifiers
    payload["target_asset_id"] = asset_b_tag

    resp = client.post("/api/v1/agents/enroll", json=payload)
    assert resp.status_code == 200
    dev_id = resp.get_json()["device_id"]

    with app.app_context():
        dev = PhysicalDevice.query.filter_by(device_id=dev_id).first()
        link_a = AssetDeviceLink.query.filter_by(device_id=dev.id, asset_id=asset_a_id).first()
        link_b = AssetDeviceLink.query.filter_by(device_id=dev.id, asset_id=asset_b_id).first()
        assert link_a is not None
        assert link_a.relationship_status == RelationshipStatus.ACTIVE
        assert link_b is None


def test_concurrent_token_use_exactly_one_wins(tmp_path):
    """Concurrent enrollment attempts with the same pairing token: exactly 1 wins, rest get 400."""
    db_file = tmp_path / "concurrent_token.db"
    db_url = f"sqlite:///{db_file}"
    engine_opts = {"connect_args": {"timeout": 30}}

    init_app = create_app(
        "testing",
        test_config={"SQLALCHEMY_DATABASE_URI": db_url, "SQLALCHEMY_ENGINE_OPTIONS": engine_opts},
    )
    with init_app.app_context():
        with db.engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.commit()
        db.create_all()

        asset = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="ASSET-CONC-TOK")
        db.session.add(asset)
        db.session.commit()
        raw_token, _ = create_token_for_asset(asset.id)
        db.session.commit()
        asset_id = asset.id

    def enroll_worker(worker_idx):
        worker_app = create_app(
            "testing",
            test_config={
                "SQLALCHEMY_DATABASE_URI": db_url,
                "SQLALCHEMY_ENGINE_OPTIONS": engine_opts,
            },
        )
        payload, _ = create_test_endpoint_payload(
            token=raw_token, hardware_suffix=f"worker-{worker_idx}"
        )
        with worker_app.test_client() as worker_client:
            res = worker_client.post(
                "/api/v1/agents/enroll",
                json=payload,
                environ_base={"REMOTE_ADDR": f"10.10.1.{worker_idx + 1}"},
            )
            return res.status_code

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(enroll_worker, range(6)))

    assert results.count(200) == 1
    assert results.count(400) == 5

    with init_app.app_context():
        active_links = AssetDeviceLink.query.filter_by(
            asset_id=asset_id,
            relationship_status=RelationshipStatus.ACTIVE,
        ).count()
        assert active_links == 1


def test_token_never_in_logs(app, client, caplog):
    """Sensitive pairing tokens and signatures are never logged or stored in cleartext."""
    caplog.set_level(logging.DEBUG)

    with app.app_context():
        asset = Asset(asset_id=generate_next_asset_id(db.session), asset_tag="ASSET-LOG-REDACTION")
        db.session.add(asset)
        db.session.commit()

        raw_tok, _ = create_token_for_asset(asset.id)
        db.session.commit()

    payload, _ = create_test_endpoint_payload(token=raw_tok, hardware_suffix="log-test")
    resp = client.post("/api/v1/agents/enroll", json=payload)
    assert resp.status_code == 200

    # Assert raw token is nowhere in response JSON
    resp_text = resp.get_data(as_text=True)
    assert raw_tok not in resp_text

    # Assert raw token is nowhere in caplog records
    for record in caplog.records:
        formatted = record.getMessage()
        assert raw_tok not in formatted
        if hasattr(record, "msg") and isinstance(record.msg, str):
            assert raw_tok not in record.msg

    # Assert raw token is nowhere in audit logs
    with app.app_context():
        audit_rows = AuditLog.query.all()
        for row in audit_rows:
            row_str = f"{row.entity_id} {row.old_value} {row.new_value} {row.metadata_json}"
            assert raw_tok not in row_str

    # Unit-test RedactingFilter directly
    rf = RedactingFilter()
    sample_text = f"Attempting enrollment with {raw_tok} and X-Signature: {'a' * 50}="
    redacted = rf.redact(sample_text)
    assert raw_tok not in redacted
    assert "PAIR-[REDACTED]" in redacted
    assert "X-Signature: [REDACTED]" in redacted


def test_every_route_has_policy(app):
    """Every route under /api/ (except /healthz) must have a registered security policy."""
    missing_policies = []
    for rule in app.url_map.iter_rules():
        rule_str = str(rule)
        if not rule_str.startswith("/api/"):
            continue
        if rule_str == "/healthz":
            continue
        if rule.endpoint not in ENDPOINT_POLICY:
            missing_policies.append((rule_str, rule.endpoint))

    assert not missing_policies, f"Endpoints missing security policy: {missing_policies}"


@pytest.mark.parametrize(
    ("status", "endpoint", "method", "expected_allowed"),
    [
        # Heartbeat
        (DeviceStatus.ACTIVE, "/api/v1/agents/heartbeat", "POST", True),
        (DeviceStatus.OFFLINE, "/api/v1/agents/heartbeat", "POST", True),
        (DeviceStatus.PENDING_VERIFICATION, "/api/v1/agents/heartbeat", "POST", True),
        (DeviceStatus.PENDING_REVERIFICATION, "/api/v1/agents/heartbeat", "POST", True),
        (DeviceStatus.UNCLAIMED, "/api/v1/agents/heartbeat", "POST", False),
        (DeviceStatus.SUSPENDED, "/api/v1/agents/heartbeat", "POST", False),
        (DeviceStatus.REVOKED, "/api/v1/agents/heartbeat", "POST", False),
        (DeviceStatus.RETIRED, "/api/v1/agents/heartbeat", "POST", False),
        # Telemetry
        (DeviceStatus.ACTIVE, "/api/v1/agents/telemetry", "POST", True),
        (DeviceStatus.OFFLINE, "/api/v1/agents/telemetry", "POST", True),
        (DeviceStatus.PENDING_VERIFICATION, "/api/v1/agents/telemetry", "POST", False),
        (DeviceStatus.PENDING_REVERIFICATION, "/api/v1/agents/telemetry", "POST", False),
        (DeviceStatus.UNCLAIMED, "/api/v1/agents/telemetry", "POST", False),
        (DeviceStatus.SUSPENDED, "/api/v1/agents/telemetry", "POST", False),
        (DeviceStatus.REVOKED, "/api/v1/agents/telemetry", "POST", False),
        (DeviceStatus.RETIRED, "/api/v1/agents/telemetry", "POST", False),
        # Jobs
        (DeviceStatus.ACTIVE, "/api/v1/agents/jobs", "GET", True),
        (DeviceStatus.OFFLINE, "/api/v1/agents/jobs", "GET", False),
        (DeviceStatus.PENDING_VERIFICATION, "/api/v1/agents/jobs", "GET", False),
        (DeviceStatus.PENDING_REVERIFICATION, "/api/v1/agents/jobs", "GET", False),
        (DeviceStatus.UNCLAIMED, "/api/v1/agents/jobs", "GET", False),
        (DeviceStatus.SUSPENDED, "/api/v1/agents/jobs", "GET", False),
        (DeviceStatus.REVOKED, "/api/v1/agents/jobs", "GET", False),
        (DeviceStatus.RETIRED, "/api/v1/agents/jobs", "GET", False),
    ],
)
def test_policy_matrix(app, client, status, endpoint, method, expected_allowed):
    """Verify state x endpoint policy matrix conforms precisely to the specification."""
    dev_id, key = create_enrolled_device(app, status=status)
    body = b'{"timestamp": 1234567890}' if method == "POST" else b""

    headers = sign_request(dev_id, key, method, endpoint, body)
    if method == "POST":
        headers["Content-Type"] = "application/json"
        resp = client.post(endpoint, data=body, headers=headers)
    else:
        resp = client.get(endpoint, headers=headers)

    if expected_allowed:
        assert resp.status_code != 403, f"Expected {status} on {endpoint} to be allowed, got 403"
    else:
        assert resp.status_code == 403, (
            f"Expected {status} on {endpoint} to be denied (403), got {resp.status_code}"
        )
        assert resp.get_json()["error"] == "device_blocked"
