# HashFlog
File-based credential vault: SHA-256 email IDs, bcrypt-salted passwords, each record Fernet-encrypted and appended to one log + tiny index for O(1) look-ups. No database, two files, scales to millions of users; ideal for secure prototypes, IoT, and web apps.

**HashFlog** is a file-based credential vault that stores every user record in three concentric security layers—SHA-256 e-mail digests, bcrypt-salted passwords, and Fernet encryption—written to a single append-only log with a compact index.

## Highlights
- **No database required**: two runtime files (`users.log`, `users.idx`)
- **Constant-time look-ups**: one disk seek and decrypt per login, even with ~1M+ users
- **Crash-safe**: append-only design; optional compactor rewrites a slim log off-peak
- **Portable**: works anywhere Python runs; depends only on `bcrypt` and `cryptography`
- **MIT-licensed**: permissive for commercial or personal use

## Storage model
1. E-mail → SHA-256 digest → UID (plain addresses never stored)  
2. Password → bcrypt hash (cost 14, salted)  
3. Hash → Fernet ciphertext  
4. `[LEN][CIPHERTEXT]` appended to **users.log**  
5. `UID OFFSET` line appended to **users.idx**

### Setup note
- Generate fernet and store as environment variable permanently under name 'FILE_ENCRYPTION_KEY', to use this package.
