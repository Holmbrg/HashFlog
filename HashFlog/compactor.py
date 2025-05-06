"""
compactor.py
============

Off-peak maintenance script to defragment **users.log**.

Run:
    python -m encryption_backend.compactor
"""

from .store import LOG_FILE, IDX_FILE

NEW_LOG = LOG_FILE.with_suffix(".new.log")
NEW_IDX = IDX_FILE.with_suffix(".new.idx")


def compact() -> None:
    """
    Stream the current append-only log into a fresh file, writing only
    the most-recent record for each UID.  When finished, atomically
    replace the old log/index.
    """

    # Build an in-memory map of uid → (offset, length)
    uid_latest: dict[str, tuple[int, int]] = {}
    with LOG_FILE.open("rb") as src:
        offset = 0
        while True:
            length_bytes = src.read(4)
            if not length_bytes:
                break
            length = int.from_bytes(length_bytes, "big")
            uid_latest[offset] = (offset + 4, length)  # store pointer → (start, len)
            src.seek(length, 1)
            offset = src.tell()

    # Reverse map: we need final position for each uid
    # Re-open index to know which offset belongs to which uid
    uid_to_offset: dict[str, int] = {}
    with IDX_FILE.open("r", encoding="utf-8") as idx:
        for line in idx:
            uid, off = line.rstrip("\n").split(" ")
            uid_to_offset[uid] = int(off)

    # Write new log + new idx
    with NEW_LOG.open("wb") as dst_log, NEW_IDX.open("w", encoding="utf-8") as dst_idx:
        for uid, old_off in uid_to_offset.items():
            start, length = uid_latest[old_off]
            with LOG_FILE.open("rb") as src:
                src.seek(start)
                blob = src.read(length)

            new_off = dst_log.tell()
            dst_log.write(len(blob).to_bytes(4, "big") + blob)
            dst_idx.write(f"{uid} {new_off}\n")

    NEW_LOG.replace(LOG_FILE)
    NEW_IDX.replace(IDX_FILE)
    print("Compaction complete.")


if __name__ == "__main__":
    compact()
