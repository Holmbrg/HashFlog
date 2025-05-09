"""
store.py
========

Append-only credential store (no external database):

* **users.log** – binary, length-prefixed ciphertext records
* **users.idx** – text, “<uid> <offset>” per line

Lookup = one seek + one small decrypt.
Register = one append to log + one append to index.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Final

from .crypto import EncryptUser

__all__ = ["UserStore"]

# Runtime files live in ./data/
DATA_DIR: Final = Path("data")
DATA_DIR.mkdir(exist_ok=True)

LOG_FILE: Final = DATA_DIR / "users.log"
IDX_FILE: Final = DATA_DIR / "users.idx"


class UserStore:
    """
    High-level *register* / *verify* interface used by the web layer.
    """

    _LEN_BYTES = 4  # 32-bit length prefix

    def __init__(
        self,
        log_path: Path | str = LOG_FILE,
        idx_path: Path | str = IDX_FILE,
        crypto: EncryptUser | None = None,
    ) -> None:
        self.log = Path(log_path)
        self.idx = Path(idx_path)
        self.c = crypto or EncryptUser()
        self._uid_to_offset: dict[str, int] = self._load_index()

    # ------------------------------------------------------------------ #
    #  Index helpers                                                     #
    # ------------------------------------------------------------------ #
    def _load_index(self) -> dict[str, int]:
        if not self.idx.exists():
            return {}
        mapping: dict[str, int] = {}
        with self.idx.open("r", encoding="utf-8") as file:
            for line in file:
                uid, off = line.rstrip("\n").split(" ")
                mapping[uid] = int(off)
        return mapping

    def _append_index(self, uid: str, offset: int) -> None:
        with self.idx.open("a", encoding="utf-8") as file:
            file.write(f"{uid} {offset}\n")
        self._uid_to_offset[uid] = offset

    # ------------------------------------------------------------------ #
    #  Public API                                                        #
    # ------------------------------------------------------------------ #
    def register(self, email: str, password: str) -> None:
        """
        Add / update a user credential.
        """

        uid = self.c.uid(email)
        cipher = self.c.enc_str(self.c.hash_pw(password))

        record = len(cipher).to_bytes(self._LEN_BYTES, "big") + cipher

        with self.log.open("ab+") as f:
            f.seek(0, io.SEEK_END)
            offset = f.tell()
            f.write(record)

        self._append_index(uid, offset)

    def verify(self, email: str, password: str) -> bool:
        """
        Return True iff *(email, password)* is valid.
        """

        uid = self.c.uid(email)
        offset = self._uid_to_offset.get(uid)
        if offset is None:
            return False

        with self.log.open("rb") as f:
            f.seek(offset)
            length = int.from_bytes(f.read(self._LEN_BYTES), "big")
            cipher = f.read(length)

        try:
            stored_hash = self.c.dec_str(cipher)
        except RuntimeError:
            return False

        return self.c.check_pw(password, stored_hash)
