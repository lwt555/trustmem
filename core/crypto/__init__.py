"""TrustMem cryptography layer — simulated CP-ABE + CKKS for Windows compatibility."""
from .abe import (
    ABEMasterKey, ABEPublicKey, ABEAttributeKey,
    Ciphertext,
    abe_setup, abe_issue_key, abe_encrypt, abe_decrypt,
    check_policy, policy_satisfied,
)
from .ckks import (
    CKKSContext, CKKSEncryptedVector,
    ckks_setup, ckks_encode_encrypt, ckks_add, ckks_multiply,
    ckks_decrypt_decode, ckks_inner_product,
)
from .engine import CryptoEngine
