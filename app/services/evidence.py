"""PB6 "preserve evidence": write an incident's evidence bundle to S3 with Object Lock in COMPLIANCE mode.

Once written, nobody can delete or overwrite that object version until retention ends: not the app, not an admin,
not the root user. The instance role can put objects and set retention but is explicitly denied delete
(infra/compineu.yaml). Credentials come from the instance role on the box, or the AWS profile on a laptop.

Called from the workflow's finalize step after an analyst approves PB6:

    from app.services.evidence import preserve_evidence
    receipt = preserve_evidence(db, case_id, bundle, approved_by="analyst@x", reason="...")

The receipt (bucket, key, version, sha256, retain-until) is written to the append-only audit trail.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from sqlalchemy.orm import Session

from app.config import aws_region, get_settings
from app.services.audit import write_event


class EvidenceError(RuntimeError):
    pass


_client = None


def _s3():
    global _client
    if _client is None:
        settings = get_settings()
        _client = boto3.client("s3", region_name=aws_region(settings))
    return _client


def preserve_evidence(db: Session, case_id: int, bundle: dict[str, Any], *, approved_by: str, reason: str,
                      client=None) -> dict[str, Any]:
    """Store `bundle` (timeline, cited event IDs, report, decision) under Object Lock and audit the receipt.

    `client` lets tests pass a stub S3 client. Raises EvidenceError if the bucket is not configured or S3 refuses.
    """
    settings = get_settings()
    if not settings.evidence_bucket:
        raise EvidenceError("EVIDENCE_BUCKET is not set; PB6 cannot run")

    now = datetime.now(timezone.utc)
    retain_until = now + timedelta(days=settings.evidence_retention_days)
    body = json.dumps(
        {"case_id": case_id, "preserved_at": now.isoformat(), "approved_by": approved_by, "reason": reason,
         "evidence": bundle},
        sort_keys=True, default=str, separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(body).hexdigest()
    key = f"incidents/{case_id}/{now.strftime('%Y%m%dT%H%M%SZ')}-{digest[:12]}.json"

    s3 = client or _s3()
    try:
        resp = s3.put_object(
            Bucket=settings.evidence_bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
            ChecksumAlgorithm="SHA256",
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until,
            Metadata={"case-id": str(case_id), "sha256": digest},
        )
    except Exception as exc:  # botocore ClientError / NoCredentialsError, surfaced to the decision endpoint
        raise EvidenceError(f"S3 refused the evidence write: {exc}") from exc

    receipt = {
        "bucket": settings.evidence_bucket,
        "key": key,
        "version_id": resp.get("VersionId"),
        "sha256": digest,
        "bytes": len(body),
        "object_lock_mode": "COMPLIANCE",
        "retain_until": retain_until.isoformat(),
        "approved_by": approved_by,
    }
    write_event(db, case_id, "playbook", "PB6_evidence_preserved", receipt)
    return receipt
