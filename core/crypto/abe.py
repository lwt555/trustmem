"""
CP-ABE (Ciphertext-Policy Attribute-Based Encryption) — KEM 仿真档（路线 B）。

诚实声明（对照《TrustMem 修补工程提示词》F-10 路线 B）：
    - 本模块**不是**真双线性配对 CP-ABE，而是「密钥隔离 KEM + AES-GCM」的仿真。
    - 核心性质：**不再存在任何一把被所有主体共享的主密钥**。每个主体只拿到
      自己属性集合对应的派生密钥（KDF(master, attr)），拿不到 master、拿不到别人
      属性的密钥。解密完全靠密钥材料本身——不满足属性的主体在密码学层面解不开，
      没有「软件 if」。
    - 访问结构按 AND-of-OR（policy_from_label 的输出形态）用 XOR 秘密分享展开：
      每个 OR 子句内的任意一个属性都能解开该子句的份额，所有子句份额异或还原 CEK。
    - 仿真档的「公钥」与「主密钥」同为权威侧持有的秘密（无真公/私分离）；只有权威
      （CryptoEngine）持有，主体永远只拿到 ABEAttributeKey。

生产环境应替换为 charm-crypto / bswabe 的真配对实现（见 core/crypto/charm_backend.py）。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 后端执法级别（F-10 验收：engine.stats() 必须如实上报，不允许 "software-if"）
ENFORCEMENT = "kem-derived"


def _kdf(master: bytes, label: str) -> bytes:
    """从一个 master 秘密派生一把子密钥（HMAC-SHA256 PRF）。单向，不可反推 master。

    这里的 master 是 32 字节真随机秘密（非低熵口令），无需 PBKDF2 拉伸；用 HMAC
    作为 PRF 既快又安全。
    """
    return hmac.new(master, label.encode("utf-8"), hashlib.sha256).digest()


def _attr_key(master: bytes, attr: str) -> bytes:
    """单个属性对应的包装密钥 K_attr = KDF(master, "attr:<name>")。"""
    return _kdf(master, f"attr:{attr}")


def _xor(*parts: bytes) -> bytes:
    out = parts[0]
    for p in parts[1:]:
        out = bytes(a ^ b for a, b in zip(out, p))
    return out


# ──────────────────────────────────────────────────────────────
# Key types
# ──────────────────────────────────────────────────────────────

@dataclass
class ABEMasterKey:
    """属性权威的主密钥。只由权威（CryptoEngine）持有，绝不下发给主体。"""
    key_bytes: bytes
    version: int = 1

    def attr_key(self, attr: str) -> bytes:
        return _attr_key(self.key_bytes, attr)

    def export(self) -> bytes:
        return self.key_bytes


@dataclass
class ABEPublicKey:
    """公钥参数。仿真档下与主密钥同为权威侧持有的秘密（无真公/私分离）。"""
    key_bytes: bytes
    version: int = 1

    def attr_key(self, attr: str) -> bytes:
        return _attr_key(self.key_bytes, attr)

    def export(self) -> bytes:
        return self.key_bytes


@dataclass
class ABEAttributeKey:
    """发给主体的属性私钥：只有其自身属性集合对应的派生密钥，无 master、无共享密钥。"""
    agent_id: str
    attributes: list[str]
    keys: dict[str, bytes]       # attr -> K_attr（仅自身属性）
    epoch: int = 0

    def has_attr(self, name: str) -> bool:
        return name in self.attributes


@dataclass
class Ciphertext:
    """CP-ABE 密文 = AES-GCM(CEK, 正文) + 每个 OR 子句的 CEK 份额包装。"""
    policy: str
    nonce: bytes
    ct: bytes                     # AES-GCM ciphertext（CEK 加密正文）
    wrapped: list = field(default_factory=list)   # clause -> [{"attr","nonce","ct"}, ...]
    tag: bytes | None = None      # auth tag if separate from ct

    def to_bytes(self) -> bytes:
        return json.dumps({
            "policy": self.policy,
            "nonce": self.nonce.hex(),
            "ct": self.ct.hex(),
            "tag": self.tag.hex() if self.tag else "",
            "wrapped": self.wrapped,
        }).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "Ciphertext":
        d = json.loads(data.decode())
        return cls(
            policy=d["policy"],
            nonce=bytes.fromhex(d["nonce"]),
            ct=bytes.fromhex(d["ct"]),
            tag=bytes.fromhex(d["tag"]) if d.get("tag") else None,
            wrapped=d.get("wrapped", []),
        )


# ──────────────────────────────────────────────────────────────
# Policy parser
# ──────────────────────────────────────────────────────────────

def _tokenize(policy: str) -> list[str]:
    """Tokenize a bswabe-style policy string. Supports hyphens in identifiers."""
    return re.findall(r'\(|\)|\band\b|\bor\b|[-\w]+', policy, re.IGNORECASE)


def _eval_policy(attributes: list[str], tokens: list[str], pos: int) -> tuple[bool, int]:
    """Recursive descent policy evaluator. Returns (result, new_pos).

    Delegates to _eval_or at the top level, then _eval_and, then _eval_atom.
    The and/or chain evaluators handle operator precedence correctly:
    'or' chains _eval_and groups, 'and' chains atoms within each or-branch.
    """
    return _eval_or(attributes, tokens, pos)


def _eval_or(attributes: list[str], tokens: list[str], pos: int) -> tuple[bool, int]:
    """Evaluate top-level and/or chain."""
    left, pos = _eval_and(attributes, tokens, pos)
    while pos < len(tokens) and tokens[pos].lower() == 'or':
        right, pos = _eval_and(attributes, tokens, pos + 1)
        left = left or right
    return left, pos


def _eval_and(attributes: list[str], tokens: list[str], pos: int) -> tuple[bool, int]:
    """Evaluate and-chain."""
    left, pos = _eval_atom(attributes, tokens, pos)
    while pos < len(tokens) and tokens[pos].lower() == 'and':
        right, pos = _eval_atom(attributes, tokens, pos + 1)
        left = left and right
    return left, pos


def _eval_atom(attributes: list[str], tokens: list[str], pos: int) -> tuple[bool, int]:
    """Evaluate a single atom (attribute name or parenthesized group)."""
    token = tokens[pos]

    if token == '(':
        pos += 1
        result, pos = _eval_or(attributes, tokens, pos)
        if pos < len(tokens) and tokens[pos] == ')':
            pos += 1
        return result, pos

    return token in attributes, pos + 1


def policy_satisfied(policy: str, attributes: list[str]) -> bool:
    """Check whether a set of attributes satisfies a CP-ABE policy string."""
    if not policy:
        return False
    try:
        tokens = _tokenize(policy)
        attr_set = set(attributes)
        result, _ = _eval_policy(list(attr_set), tokens, 0)
        return result
    except (IndexError, ValueError):
        return False


def check_policy(policy: str, attributes: list[str]) -> tuple[bool, str]:
    """Return (satisfied, explanation)."""
    ok = policy_satisfied(policy, attributes)
    if ok:
        return True, f"[PASS] 属性集合满足策略: {policy}"
    else:
        return False, f"[FAIL] 属性集合不满足策略: {policy}"


class _PolicyParser:
    """把单调布尔策略展开为最小属性集族（DNF 最小项）。

    AND → 笛卡尔积合并；OR → 取并。真 CP-ABE 支持任意单调布尔式，
    本仿真用同样的语义展开（可能指数级，policy_from_label 产出的 AND-of-OR
    项数有界）。
    """

    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _advance(self) -> str:
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def parse_or(self) -> list[frozenset[str]]:
        result = self.parse_and()
        while self._peek() is not None and self._peek().lower() == 'or':
            self._advance()
            result = result + self.parse_and()
        return result

    def parse_and(self) -> list[frozenset[str]]:
        result = self.parse_factor()
        while self._peek() is not None and self._peek().lower() == 'and':
            self._advance()
            right = self.parse_factor()
            result = [a | b for a in result for b in right]
        return result

    def parse_factor(self) -> list[frozenset[str]]:
        t = self._peek()
        if t == '(':
            self._advance()
            result = self.parse_or()
            if self._peek() == ')':
                self._advance()
            return result
        self._advance()
        return [frozenset([t])]


def _minimal_sets(policy: str) -> list[frozenset[str]]:
    """返回满足策略的最小属性集族（DNF 最小项）。空策略 → 无人可解。"""
    if not policy.strip():
        return []
    tokens = _tokenize(policy)
    if not tokens:
        return []
    try:
        return _PolicyParser(tokens).parse_or()
    except IndexError:
        return []


# ──────────────────────────────────────────────────────────────
# CP-ABE API (charm-compatible interface, KEM simulation)
# ──────────────────────────────────────────────────────────────

def abe_setup() -> tuple[ABEMasterKey, ABEPublicKey]:
    """生成主密钥与公钥参数。仿真档下二者同为权威侧持有的秘密。"""
    mk_bytes = os.urandom(32)
    return ABEMasterKey(mk_bytes), ABEPublicKey(mk_bytes)


def abe_issue_key(mk: ABEMasterKey, agent_id: str,
                  attributes: list[str], epoch: int = 0) -> ABEAttributeKey:
    """签发属性私钥：只给主体自身属性集合对应的派生密钥，不给 master。"""
    keys = {attr: mk.attr_key(attr) for attr in attributes}
    return ABEAttributeKey(agent_id=agent_id, attributes=list(attributes),
                           keys=keys, epoch=epoch)


def abe_encrypt(pk: ABEPublicKey, plaintext: str, policy: str) -> Ciphertext:
    """
    按策略加密明文。KEM + 秘密分享：

      1. 随机生成 CEK，AES-GCM 加密正文；
      2. 策略展开为最小属性集族（DNF 最小项）；
      3. 对每个最小项，把 CEK 用 XOR 拆成 |minterm| 份，每份用对应属性的
         K_attr = KDF(master, attr) 包装。满足任一最小项即能还原 CEK。
    """
    minterms = _minimal_sets(policy)
    cek = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(cek)
    ct_body = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), policy.encode())  # AAD = policy

    wrapped: list[list[dict[str, str]]] = []
    for minterm in minterms:
        attrs = sorted(minterm)
        n = len(attrs)
        random_shares = [os.urandom(32) for _ in range(max(0, n - 1))]
        shares = list(random_shares) + [_xor(cek, *random_shares)]
        clause_wrapped: list[dict[str, str]] = []
        for attr, share in zip(attrs, shares):
            ka = pk.attr_key(attr)
            an = os.urandom(12)
            aw = AESGCM(ka).encrypt(an, share, b"wrap")
            clause_wrapped.append({"attr": attr, "nonce": an.hex(), "ct": aw.hex()})
        wrapped.append(clause_wrapped)

    return Ciphertext(policy=policy, nonce=nonce, ct=ct_body, wrapped=wrapped)


def _recover_cek(attr_key: ABEAttributeKey, wrapped: list) -> bytes | None:
    """逐个最小项尝试用主体自身的属性密钥解包份额、异或还原 CEK。

    没有任何软件策略判断——凑不齐任一最小项的全部属性，就无法还原 CEK，
    密码学层面解不开。
    """
    for clause_wrapped in wrapped:
        shares: list[bytes] = []
        ok = True
        for w in clause_wrapped:
            ka = attr_key.keys.get(w["attr"])
            if ka is None:
                ok = False
                break
            try:
                shares.append(AESGCM(ka).decrypt(
                    bytes.fromhex(w["nonce"]), bytes.fromhex(w["ct"]), b"wrap"))
            except Exception:
                ok = False
                break
        if ok and shares:
            return _xor(*shares)
    return None


def abe_decrypt(attr_key: ABEAttributeKey, ct: Ciphertext) -> bytes | None:
    """解密。返回 None 表示主体属性在密码学层面不足以解开（无软件 if）。"""
    cek = _recover_cek(attr_key, ct.wrapped)
    if cek is None:
        return None
    aesgcm = AESGCM(cek)
    try:
        return aesgcm.decrypt(ct.nonce, ct.ct, ct.policy.encode())
    except Exception:
        return None
