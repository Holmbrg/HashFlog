"""
Command-line wrapper:  verify login credentials.

Usage:
    python main_login.py email@example.com "plain-text-password"

Exit code 0 when credentials are valid, 1 otherwise.
Stdout → {"valid": true/false}
"""

import json
import sys
from hashflog.store import UserStore


def main() -> None:
    """
    Command-line credential check.

    This wrapper expects exactly two positional arguments on
    ``sys.argv``—the user’s e-mail address and plaintext password—
    then verifies them via :pyclass:`encryption_backend.UserStore`.

    Workflow
    --------
    1.  Validate argument count (must be 3 incl. program name).
    2.  Call :py:meth:`UserStore.verify`.
    3.  Emit a one-line JSON object to *stdout*::

            {"valid": true}          # on success
            {"valid": false, "msg": "..."}  # on failure or error

    Exit Codes
    ----------
    * ``0`` – credentials are valid
    * ``1`` – login failed or an exception occurred

    Notes
    -----
    The script is intended for inter-process use; language-agnostic
    front-ends can parse the JSON and rely on the exit status without
    importing any Python modules.
    """

    if len(sys.argv) != 3:
        print(json.dumps({"valid": False, "msg": "usage: login email password"}))
        sys.exit(1)

    email, password = sys.argv[1], sys.argv[2]
    try:
        ok = UserStore().verify(email, password)
    except Exception as exc:  # pylint: disable=broad-except
        print(json.dumps({"valid": False, "msg": str(exc)}))
        sys.exit(1)

    print(json.dumps({"valid": ok}))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
