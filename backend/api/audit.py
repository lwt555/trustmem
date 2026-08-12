"""Audit endpoints — Merkle proof, session replay, chain verification."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .schemas import (
    AuditEventInfo, MerkleProofInfo,
    SessionReplayResponse, ChainVerificationResponse,
)
from .deps import get_merkle_audit

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _audit_event_to_info(event) -> AuditEventInfo:
    return AuditEventInfo(
        event_id=event.event_id,
        event_type=event.event_type.value,
        subject=event.subject,
        object=event.object,
        session_id=event.session_id,
        payload=event.payload,
        at=event.at.isoformat(),
    )


@router.get("/events/{event_id}", response_model=AuditEventInfo)
def get_audit_event(event_id: str):
    ma = get_merkle_audit()
    evt = ma.get_event(event_id)
    if evt is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return _audit_event_to_info(evt)


@router.get("/proof/{event_id}", response_model=MerkleProofInfo)
def get_audit_proof(event_id: str):
    ma = get_merkle_audit()
    proof = ma.get_proof(event_id)
    if proof is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return MerkleProofInfo(
        leaf_hash=proof.leaf_hash.hex(),
        root=proof.root.hex(),
        leaf_index=proof.leaf_index,
        siblings=[(h.hex(), side) for h, side in proof.siblings],
        valid=proof.verify(),
    )


@router.get("/session/{session_id}", response_model=SessionReplayResponse)
def replay_session(session_id: str):
    ma = get_merkle_audit()
    events = ma.replay_session(session_id)
    return SessionReplayResponse(
        session_id=session_id,
        total_events=len(events),
        events=[_audit_event_to_info(e) for e in events],
    )


@router.get("/chain/verify", response_model=ChainVerificationResponse)
def verify_chain():
    ma = get_merkle_audit()
    result = ma.verify_chain()
    return ChainVerificationResponse(
        valid=result["valid"],
        chain_length=result["chain_length"],
        blocks=result["blocks"],
    )


@router.get("/events")
def list_audit_events(session_id: str | None = None, limit: int = 50):
    ma = get_merkle_audit()
    if session_id:
        events = ma.replay_session(session_id)
    else:
        events = []
    events = events[-limit:]
    return {"events": [_audit_event_to_info(e) for e in events]}
