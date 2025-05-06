"""
crypto.py
=========

Low-level primitives shared by the credential store:

* Fernet wrappers (encrypt / decrypt bytes or strings)
* bcrypt helpers (hash / verify) – cost 14 by default
* SHA-256 digests of e-mail addresses (deterministic UID)

Please note: with cmd, setx a FILE_ENCRYPTION_KEY, before
use.
"""

from __future__ import annotations

import os
from hashlib import sha256

import bcrypt
from cryptography.fernet import Fernet, InvalidToken


__all__ = ["EncryptUser"]


class EncryptUser:
    """
    All cryptographic helpers bundled in one class.
    """

    # ------------------------------------------------------------------ #
    #  Constructor                                                       #
    # ------------------------------------------------------------------ #
    def __init__(self, key: str | None = None) -> None:
        """
        Parameters
        ----------
        key : str | None
            32-byte base-64 Fernet key.  If *None* we read the key from
            ``FILE_ENCRYPTION_KEY`` in the environment.
        """
        key = key or os.getenv("FILE_ENCRYPTION_KEY", "")
        if not key:
            raise RuntimeError("FILE_ENCRYPTION_KEY not set")

        self._fernet = Fernet(key.encode())

    # ------------------------------------------------------------------ #
    #  Fernet helpers                                                    #
    # ------------------------------------------------------------------ #
    def enc_bytes(self, blob: bytes) -> bytes:
        """Encrypt arbitrary bytes → ciphertext bytes."""
        return self._fernet.encrypt(blob)

    def dec_bytes(self, token: bytes) -> bytes:
        """Decrypt ciphertext bytes → plaintext bytes."""
        try:
            return self._fernet.decrypt(token)
        except InvalidToken as exc:
            raise RuntimeError("Bad token or wrong key") from exc

    def enc_str(self, txt: str) -> bytes:
        """Encrypt UTF-8 string → ciphertext bytes."""
        return self.enc_bytes(txt.encode())

    def dec_str(self, token: bytes) -> str:
        """Decrypt ciphertext bytes → UTF-8 string."""
        return self.dec_bytes(token).decode()

    # ------------------------------------------------------------------ #
    #  bcrypt helpers                                                    #
    # ------------------------------------------------------------------ #
    @staticmethod
    def hash_pw(pw: str, rounds: int = 14) -> str:
        """Return bcrypt hash of *pw* (cost = *rounds*)."""
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds)).decode()

    @staticmethod
    def check_pw(pw: str, stored_hash: str) -> bool:
        """Verify *pw* against *stored_hash*."""
        return bcrypt.checkpw(pw.encode(), stored_hash.encode())

    # ------------------------------------------------------------------ #
    #  UID helper                                                        #
    # ------------------------------------------------------------------ #
    @staticmethod
    def uid(email: str) -> str:
        """Deterministic SHA-256 hex digest of the e-mail address."""
        return sha256(email.encode()).hexdigest()
