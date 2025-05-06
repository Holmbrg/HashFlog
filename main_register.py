"""
Command-line wrapper:  register a new user.

Usage (shell):
    python main_register.py email@example.com "plain-text-password"

Return code: 0 on success, 1 on error.
Prints a JSON object to stdout so other processes can parse it.
"""

import json
import sys
from HashFlog.store import UserStore


def main() -> None:
    """
    Command-line user registration helper.

    The script is designed for non-Python front-ends (or manual CLI use)
    that need to create a new credential record without importing the
    full `encryption_backend` package.

    Expected CLI
    ------------
    ``python main_register.py <email> <password>``

    * *email*  – user’s e-mail address (plain text)
    * *password* – user’s chosen password (plain text)

    Behaviour
    ---------
    1.  Verifies the argument count (must be exactly two arguments
        besides the program name).
    2.  Delegates to :py:meth:`encryption_backend.UserStore.register`
        which performs:
        * SHA-256 digest of the e-mail → UID
        * bcrypt hash of the password (cost 14)
        * Fernet encryption of the bcrypt hash
        * Append to the encrypted log + update the index
    3.  Writes a one-line JSON object to *stdout*::

            {"status": "ok"}                         # success
            {"status": "error", "msg": "<message>"}  # failure

    Exit Codes
    ----------
    * ``0`` – Registration succeeded
    * ``1`` – Incorrect usage or exception

    Notes
    -----
    The wrapper prints structured JSON so any language can consume it
    via *stdout* and rely on the POSIX exit status.  All low-level
    cryptographic and storage details remain encapsulated inside
    :pyclass:`encryption_backend.UserStore`.
    """

    if len(sys.argv) != 3:
        print(json.dumps({"status": "error", "msg": "usage: register email password"}))
        sys.exit(1)

    email, password = sys.argv[1], sys.argv[2]
    try:
        UserStore().register(email, password)
    except Exception as exc:  # pylint: disable=broad-except
        print(json.dumps({"status": "error", "msg": str(exc)}))
        sys.exit(1)

    print(json.dumps({"status": "ok"}))


if __name__ == "__main__":
    main()
