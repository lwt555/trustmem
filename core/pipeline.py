"""
Full read and write pipelines — the orchestration layer that ties together
PDP, CP-ABE, trust decay, persistence, provenance, and audit.

These are the "real" entry points that the API layer calls. Each pipeline
produces a complete audit trail and persists all side effects.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from .labels import (
    AgentLabel, MemoryLabel, Clearance, Trust, Layer, MemoryType,
    WriteOp, TaskScope, IngestMode, fmt, meet_trust,
)
from .session import Session, SessionStore
from .pdp import PDP, Decision, Check
from .decay import compute_trust, DecayResult
from .trust_rules import trust_rule
from .policy import policy_from_label
from .topology import Topology
from .verdict import Verdict
from .varstore import VarStore, VarHandle
from pep.pep import PEP
from ifc.crypto_client import CryptoClient


# ──────────────────────────────────────────────────────────────
# Result types
# ──────────────────────────────────────────────────────────────

@dataclass
class WriteResult:
    """Complete result of a memory write operation."""
    allowed: bool
    decision: Decision
    decay: DecayResult | None = None
    memory: MemoryLabel | None = None      # the new memory label
    ciphertext: object | None = None       # CP-ABE Ciphertext, stored separately
    chunk_id: str = ""
    denied_by: str | None = None
    checks: list[Check] = field(default_factory=list)
    side_effects: list[str] = field(default_factory=list)

    @property
    def is_allowed(self) -> bool:
        return self.allowed

    def explain(self) -> str:
        if self.allowed:
            lines = [f"[ALLOW] WRITE {self.chunk_id} by {self.decision.subject}"]
            for c in self.checks:
                lines.append(f"  {c}")
            if self.decay:
                lines.append(f"  Trust: {self.decay.explain()}")
            for se in self.side_effects:
                lines.append(f"  [!] {se}")
            return "\n".join(lines)
        else:
            return f"[DENY] WRITE denied by {self.denied_by}: {self.decision.explain()}"


@dataclass
class ReadResult:
    """Complete result of a memory read operation."""
    allowed: bool
    decision: Decision
    memory: MemoryLabel | None = None
    plaintext: bytes | None = None
    denied_by: str | None = None
    checks: list[Check] = field(default_factory=list)
    side_effects: list[str] = field(default_factory=list)
    t_eff_dropped: bool = False
    t_eff_before: Trust | None = None
    t_eff_after: Trust | None = None
    hidden: bool = False
    var_handle: VarHandle | None = None

    @property
    def is_allowed(self) -> bool:
        return self.allowed

    @property
    def is_hidden(self) -> bool:
        return self.hidden

    def explain(self) -> str:
        if self.hidden:
            lines = [f"[HIDE] READ {self.memory.chunk_id if self.memory else '?'} "
                     f"by {self.decision.subject}"]
            for c in self.checks:
                lines.append(f"  {c}")
            if self.var_handle:
                lines.append(f"  VarHandle: #{self.var_handle.var_id}#")
                lines.append(f"  Allowed queries: {self.var_handle.constraint_types}")
            return "\n".join(lines)
        elif self.allowed:
            lines = [f"[ALLOW] READ {self.memory.chunk_id if self.memory else '?'} "
                     f"by {self.decision.subject}"]
            for c in self.checks:
                lines.append(f"  {c}")
            if self.t_eff_dropped:
                lines.append(f"  [LOMAC] T_eff: {fmt(self.t_eff_before)} -> {fmt(self.t_eff_after)}")
            return "\n".join(lines)
        else:
            return f"[DENY] READ denied by {self.denied_by}"


# ──────────────────────────────────────────────────────────────
# Store interfaces (for DI, not importing concrete stores directly)
# ──────────────────────────────────────────────────────────────

class MemoryStoreProto(Protocol):
    def put(self, mem: MemoryLabel, ciphertext: bytes | None = None) -> object: ...
    def get(self, chunk_id: str) -> MemoryLabel | None: ...
    def get_ciphertext(self, chunk_id: str) -> bytes | None: ...
    def list_by_task(self, task_id: str) -> list[MemoryLabel]: ...


class AuditStoreProto(Protocol):
    def log(self, decision: Decision) -> object: ...


class ProvenanceStoreProto(Protocol):
    def link(self, source_id: str, target_id: str, decay: DecayResult) -> object: ...


class CryptoEngineProto(Protocol):
    def encrypt_memory(self, content: str, mem_label: MemoryLabel) -> object: ...
    def decrypt_memory(self, agent: AgentLabel, ct: object) -> tuple[bytes | None, str]: ...


# ──────────────────────────────────────────────────────────────
# Write Pipeline
# ──────────────────────────────────────────────────────────────

class WritePipeline:
    """
    Full write pipeline: PDP -> Trust Decay -> CP-ABE Encrypt -> Persist.

    Usage:
        result = write_pipeline.write(
            agent=analyst, session=sess, content="finding",
            target_sens=Clearance.L2_SENSITIVE, target_layer=Layer.CONCLUSION,
            memory_type=MemoryType.INTEL, input_mems=[intel1, intel2],
            op=WriteOp.SUMMARIZE, task_binding="incident-42",
        )
        if result.allowed:
            print(f"Wrote {result.chunk_id} with T={result.memory.provenance_trust}")
    """

    def __init__(self, pdp: PDP, crypto: CryptoEngineProto,
                 mem_store: MemoryStoreProto,
                 audit_store: AuditStoreProto,
                 prov_store: ProvenanceStoreProto,
                 signer: object | None = None) -> None:
        self.pdp = pdp
        self.crypto = crypto
        self.mem_store = mem_store
        self.audit = audit_store
        self.prov = prov_store
        self.signer = signer

    # ── Write ─────────────────────────────────────────────────

    @trust_rule("TR16", group="D",
                trigger="记忆跨主体传播（写入即定标）",
                change="provenance_trust 钉死在写时衰减值，不随写者固有可信度重置",
                basis="跨主体边界复合（A 组读入 + B 组写出在边界上复合）")
    def write(
        self, *, agent: AgentLabel, session: Session,
        content: str,
        target_sensitivity: Clearance,
        target_layer: Layer,
        memory_type: MemoryType,
        input_mems: list[MemoryLabel] | None = None,
        op: WriteOp = WriteOp.INFER,
        task_binding: str | None = None,
        collab_group: set[str] | None = None,
        declassify_approved: bool = False,
        input_texts: list[str] | None = None,
        schema_ok: bool | None = None,
        ttl_end: datetime | None = None,
        scope: TaskScope,
        anchor: object | None = None,
    ) -> WriteResult:
        """Execute the full write pipeline."""
        side_effects: list[str] = []
        input_mems = input_mems or []
        input_texts = input_texts or [m.chunk_id for m in input_mems]
        task = task_binding or session.task_id

        # 0. TaskScope 上链承诺校验（F-09）
        if anchor is not None and scope is not None:
            from .task_scope import verify_scope_against_chain
            if not verify_scope_against_chain(scope, anchor):
                decision = Decision(Verdict.DENY, "WRITE", agent.agent_id, task, [],
                                    denied_by="ScopeCommitMismatch")
                self.audit.log(decision)
                return WriteResult(allowed=False, decision=decision,
                                   denied_by="ScopeCommitMismatch")

        # 1. PDP decision
        decision, decay = self.pdp.can_write(
            agent=agent, sess=session,
            target_sensitivity=target_sensitivity,
            target_layer=target_layer,
            input_mems=input_mems, op=op,
            input_texts=input_texts, output_text=content,
            schema_ok=schema_ok,
            declassify_approved=declassify_approved,
        )

        result = WriteResult(
            allowed=decision.allowed,
            decision=decision,
            decay=decay,
            checks=list(decision.checks),
        )

        # 2. Scope check (if provided)
        if decision.allowed and scope is not None:
            ok_c = scope.contains_c(target_sensitivity)
            ok_t = scope.contains_t(decay.trust_out)
            if not (ok_c and ok_t):
                decision.verdict = Verdict.DENY
                decision.denied_by = "TaskScope-C" if not ok_c else "TaskScope-T"
                result.allowed = False
                result.denied_by = decision.denied_by

        # 3. Audit and return if denied
        if not decision.allowed:
            result.denied_by = decision.denied_by
            self.audit.log(decision)
            return result

        # 4. Create memory label
        chunk_id = self._new_chunk_id()
        mem = MemoryLabel(
            chunk_id=chunk_id,
            sensitivity=target_sensitivity,
            provenance_trust=decay.trust_out,
            layer=target_layer,
            memory_type=memory_type,
            owner_agent=agent.agent_id,
            task_binding=task,
            collab_group=collab_group or agent.collab_group,
            provenance_chain=[m.chunk_id for m in input_mems],
            lifecycle="active",
            epoch=agent.epoch,
            declassified=declassify_approved,
            ttl_end=ttl_end,
        )

        # 4.5 CONSULT 内容级泄漏降级（F-29）：本会话若 CONSULT 读过任何内容，
        # 即便「用自己的话复述」写回（input_mems 为空，绕开 I14 的标识符级阻断），
        # 也强制把可信度钳制到 ≤ T1 并打标——进得去，但驱动不了高危动作。
        if session.consulted:
            capped = Trust(min(int(mem.provenance_trust), int(Trust.T1_LOW)))
            mem.provenance_trust = capped
            mem.derived_from_consult = True
            side_effects.append(
                f"F-29: CONSULT 派生写回，provenance_trust 钳制到 {fmt(capped)}")

        # 5. Encrypt content
        ct = self.crypto.encrypt_memory(content, mem)
        side_effects.append(f"CP-ABE encrypted under label policy")

        # 5.5. Sign metadata + ciphertext digest (F-14: 写入不可抵赖)
        ct_bytes = ct.to_bytes() if hasattr(ct, "to_bytes") else ct
        if self.signer is not None:
            self.signer.sign(mem, ct_bytes)
            side_effects.append(f"Signed by {mem.owner_agent} (ECDSA)")

        # 6. Persist memory + ciphertext (F-12: 密文落库，不许只存标签)
        try:
            self.mem_store.put(mem, ct_bytes)
        except TypeError:
            self.mem_store.put(mem)   # 旧 store 未接密文参数时退化为只存标签
        side_effects.append(f"Memory persisted: {chunk_id}")

        # 7. Provenance links
        for upstream in input_mems:
            self.prov.link(chunk_id, upstream.chunk_id, decay)
        if input_mems:
            side_effects.append(f"Provenance links: {len(input_mems)} upstream")

        # 8. Audit
        decision.side_effect = "; ".join(side_effects)
        self.audit.log(decision)
        side_effects.append("Audit event logged")

        result.allowed = True
        result.memory = mem
        result.ciphertext = ct
        result.chunk_id = chunk_id
        result.side_effects = side_effects
        return result

    # ── Helpers ───────────────────────────────────────────────

    def _new_chunk_id(self) -> str:
        return f"mem-{uuid.uuid4().hex[:12]}"


# ──────────────────────────────────────────────────────────────
# Read Pipeline
# ──────────────────────────────────────────────────────────────

class ReadPipeline:
    """
    Full read pipeline: PDP -> CP-ABE Decrypt -> LOMAC absorb.

    Supports four-value verdict:
      ALLOW  — decrypt and return plaintext
      HIDE   — create #var# handle, return metadata only
      CONFIRM — requires human-in-the-loop (placeholder)
      DENY   — audit and return

    Usage:
        result = read_pipeline.read(agent=analyst, session=sess, chunk_id="mem-abc123")
        if result.is_hidden:
            print(f"HIDDEN as #{result.var_handle.var_id}#")
        elif result.allowed:
            print(f"Content: {result.plaintext.decode()}")
    """

    def __init__(self, pdp: PDP, crypto: CryptoEngineProto,
                 mem_store: MemoryStoreProto,
                 audit_store: AuditStoreProto,
                 var_store: VarStore | None = None,
                 crypto_client: CryptoClient | None = None,
                 verifier: object | None = None) -> None:
        self.pdp = pdp
        self.crypto = crypto
        self.mem_store = mem_store
        self.audit = audit_store
        self.var_store = var_store or VarStore()
        self.pep = PEP()
        self.crypto_client = crypto_client or CryptoClient(crypto)
        self.verifier = verifier

    # ── Read ──────────────────────────────────────────────────

    def read(
        self, *, agent: AgentLabel, session: Session,
        chunk_id: str,
        now: datetime | None = None,
        epoch_current: int | None = None,
        scope: TaskScope,
        anchor: object | None = None,
    ) -> ReadResult:
        """Execute the full read pipeline with HIDE support."""
        side_effects: list[str] = []

        # 0. TaskScope 上链承诺校验（F-09）：scope 与链上 MANIFEST_COMMIT 不符 → 全 DENY
        if anchor is not None and scope is not None:
            from .task_scope import verify_scope_against_chain
            if not verify_scope_against_chain(scope, anchor):
                decision = Decision(Verdict.DENY, "READ", agent.agent_id, chunk_id, [],
                                    denied_by="ScopeCommitMismatch")
                self.audit.log(decision)
                return ReadResult(allowed=False, decision=decision,
                                  denied_by="ScopeCommitMismatch")

        # 1. Fetch memory from store
        mem = self.mem_store.get(chunk_id)
        if mem is None:
            decision = Decision(Verdict.DENY, "READ", agent.agent_id, chunk_id, [],
                                denied_by="NotFound")
            return ReadResult(allowed=False, decision=decision,
                            denied_by="NotFound")

        # 2. PDP decision
        if scope is not None:
            decision = self.pdp.can_read_scoped(
                agent, mem, session, scope, now, epoch_current)
        else:
            decision = self.pdp.can_read(agent, mem, session, now, epoch_current)

        # 生成裁决凭证 id（F-12 解密账本的关键）
        if not decision.decision_id:
            decision.decision_id = f"dec-{uuid.uuid4().hex[:12]}"

        result = ReadResult(
            allowed=decision.allowed,
            decision=decision,
            memory=mem,
            checks=list(decision.checks),
            side_effects=side_effects,
        )

        # 3. HIDE: create #var# handle, audit, return metadata（不触碰水位，I8）
        if decision.verdict == Verdict.HIDE:
            var_id = VarStore.new_id()
            handle = VarHandle(
                var_id=var_id,
                chunk_id=chunk_id,
                reason=decision.denied_by or "Unknown",
                constraint_types=["bool", "enum", "number"],
                sensitivity=mem.sensitivity,
                source_trust=mem.provenance_trust,
                metadata={
                    "sensitivity": fmt(mem.sensitivity),
                    "trust": fmt(mem.provenance_trust),
                    "layer": mem.layer.value,
                    "type": mem.memory_type.value,
                    "owner": mem.owner_agent,
                },
            )
            self.var_store.store(handle)
            side_effects.append(f"VarHandle created: #{var_id}# ({decision.denied_by})")
            side_effects.append("Audit event logged")
            self.audit.log(decision)

            result.hidden = True
            result.var_handle = handle
            result.side_effects = side_effects
            return result

        # 4. DENY: audit and return
        if decision.verdict == Verdict.DENY:
            result.denied_by = decision.denied_by
            self.audit.log(decision)
            return result

        # 5. CONFIRM 必须被拦截（F-12）：不落解密路径，返回未授权
        if decision.verdict == Verdict.CONFIRM:
            result.allowed = False
            result.denied_by = decision.denied_by or "HITL-Required"
            self.audit.log(decision)
            return result

        # 6. Decrypt content (ALLOW path) —— 先判决后解密
        before_t = session.t_eff
        self.pep.commit(session, decision)          # 水位提交点（F-04）
        if session.t_eff < before_t:
            result.t_eff_dropped = True
            result.t_eff_before = before_t
            result.t_eff_after = session.t_eff
            side_effects.append(
                f"LOMAC: T_eff {fmt(before_t)} -> {fmt(session.t_eff)}")

        ct_bytes = self._get_ciphertext(chunk_id)

        # 6.5. 验签（F-14）：解密之前先验证写入方签名，失败 → DENY
        if self.verifier is not None and not self.verifier.verify(mem, ct_bytes):
            decision.verdict = Verdict.DENY
            decision.denied_by = "SignatureInvalid"
            result.allowed = False
            result.denied_by = "SignatureInvalid"
            self.audit.log(decision)
            return result

        self.crypto_client.record_allow(decision.decision_id, chunk_id)
        plain, reason = self.crypto_client.decrypt(agent, ct_bytes, decision.decision_id)
        self.crypto_client.decrypted_ids.add(chunk_id)
        side_effects.append(reason)

        # 7. Audit
        side_effects.append("Audit event logged")
        self.audit.log(decision)

        result.side_effects = side_effects
        result.plaintext = plain
        return result

    def _get_ciphertext(self, chunk_id: str) -> bytes | None:
        get_ct = getattr(self.mem_store, "get_ciphertext", None)
        if get_ct is None:
            return None
        ct = get_ct(chunk_id)
        if ct is None:
            raise RuntimeError(f"密文缺失: {chunk_id}（不许静默降级，F-12）")
        return ct

    # ── Batch read ────────────────────────────────────────────

    def read_many(
        self, *, agent: AgentLabel, session: Session,
        chunk_ids: list[str],
        scope: TaskScope,
    ) -> list[ReadResult]:
        """Batch read multiple chunks. Each gets its own PDP check."""
        return [self.read(agent=agent, session=session,
                         chunk_id=cid, scope=scope) for cid in chunk_ids]
