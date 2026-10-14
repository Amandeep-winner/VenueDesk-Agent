"""Remote job management and lifecycle service."""

from datetime import UTC, datetime, timedelta
from typing import Any

from app.extensions import db
from app.models import (
    ActorType,
    AuditAction,
    AuditLog,
    DeviceJob,
    JobStatus,
    JobType,
    PhysicalDevice,
)


def _find_device(device_identifier: str | int) -> PhysicalDevice | None:
    """Find device by device_id string or integer primary key."""
    if isinstance(device_identifier, int):
        return db.session.get(PhysicalDevice, device_identifier)
    dev = PhysicalDevice.query.filter_by(device_id=device_identifier).first()
    if dev:
        return dev
    try:
        pk = int(device_identifier)
        return db.session.get(PhysicalDevice, pk)
    except ValueError:
        return None


def create_job(
    device_identifier: str | int,
    job_type: JobType | str,
    payload: dict[str, Any] | None = None,
    created_by: str = "system",
    expires_in_seconds: int = 3600,
) -> DeviceJob:
    """Create and dispatch a remote maintenance/diagnostic job for an endpoint.

    Validates job type against the strict allowlist and audits dispatch.
    """
    device = _find_device(device_identifier)
    if not device:
        raise ValueError(f"Device '{device_identifier}' not found")

    # Validate allowlisted job type
    if isinstance(job_type, str):
        try:
            job_type_enum = JobType(job_type)
        except ValueError:
            raise ValueError(f"Job type '{job_type}' is not allowlisted")
    elif isinstance(job_type, JobType):
        job_type_enum = job_type
    else:
        raise TypeError(f"Invalid job type specification: {job_type}")

    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=max(60, expires_in_seconds))

    job = DeviceJob(
        device_id=device.id,
        job_type=job_type_enum,
        payload=payload or {},
        status=JobStatus.PENDING,
        created_by=created_by,
        created_at=now,
        expires_at=expires_at,
    )
    db.session.add(job)
    db.session.flush()

    # Audit job dispatch
    db.session.add(
        AuditLog(
            actor_id=created_by,
            actor_type=ActorType.USER if created_by != "system" else ActorType.SYSTEM,
            action=AuditAction.IDENTITY_OVERRIDE,  # Reusing action or recording as job event
            entity_type="device_job",
            entity_id=str(job.id),
            new_value={
                "job_type": job_type_enum.value,
                "device_id": device.device_id,
                "expires_at": expires_at.isoformat(),
            },
        )
    )
    db.session.commit()
    return job


def expire_stale_jobs(device_id: int | None = None) -> int:
    """Mark expired pending/dispatched jobs as EXPIRED."""
    now = datetime.now(UTC)
    query = DeviceJob.query.filter(
        DeviceJob.status.in_([JobStatus.PENDING, JobStatus.DISPATCHED]),
        DeviceJob.expires_at < now,
    )
    if device_id is not None:
        query = query.filter_by(device_id=device_id)

    expired_jobs = query.all()
    for j in expired_jobs:
        j.status = JobStatus.EXPIRED
        j.completed_at = now

    if expired_jobs:
        db.session.commit()
    return len(expired_jobs)


def has_pending_jobs(device_id: int) -> bool:
    """Check if device has any pending, unexpired jobs awaiting dispatch."""
    now = datetime.now(UTC)
    return (
        DeviceJob.query.filter_by(device_id=device_id, status=JobStatus.PENDING)
        .filter(DeviceJob.expires_at > now)
        .first()
        is not None
    )


def get_pending_jobs_for_device(
    device_identifier: str | int,
    mark_dispatched: bool = True,
) -> list[DeviceJob]:
    """Retrieve pending jobs for a device and transition them to DISPATCHED."""
    device = _find_device(device_identifier)
    if not device:
        return []

    expire_stale_jobs(device.id)

    now = datetime.now(UTC)
    jobs = (
        DeviceJob.query.filter_by(device_id=device.id, status=JobStatus.PENDING)
        .filter(DeviceJob.expires_at > now)
        .order_by(DeviceJob.created_at.asc())
        .all()
    )

    if mark_dispatched and jobs:
        for job in jobs:
            job.status = JobStatus.DISPATCHED
            job.started_at = now
        db.session.commit()

    return jobs


def record_job_result(
    job_id: int,
    device_identifier: str | int,
    status: JobStatus | str,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> DeviceJob:
    """Record execution completion result or failure for a dispatched job."""
    device = _find_device(device_identifier)
    if not device:
        raise ValueError(f"Device '{device_identifier}' not found")

    job = db.session.get(DeviceJob, job_id)
    if not job or job.device_id != device.id:
        raise ValueError(f"Job {job_id} not found for device '{device.device_id}'")

    if isinstance(status, str):
        try:
            status_enum = JobStatus(status.upper())
        except ValueError:
            status_enum = JobStatus.FAILED
    else:
        status_enum = status

    if status_enum not in (JobStatus.SUCCEEDED, JobStatus.FAILED):
        raise ValueError(f"Invalid terminal job status: {status}")

    now = datetime.now(UTC)
    job.status = status_enum
    job.completed_at = now
    job.result = {
        "status": status_enum.value,
        "result": result or {},
        "error": error,
    }
    db.session.commit()
    return job


def get_device_jobs(
    device_identifier: str | int,
    limit: int = 100,
) -> list[DeviceJob]:
    """Retrieve job history for a device ordered newest first."""
    device = _find_device(device_identifier)
    if not device:
        return []

    expire_stale_jobs(device.id)

    return (
        DeviceJob.query.filter_by(device_id=device.id)
        .order_by(DeviceJob.created_at.desc())
        .limit(limit)
        .all()
    )
