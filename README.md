# HashFlog
File-based credential vault: SHA-256 email IDs, bcrypt-salted passwords, each record Fernet-encrypted and appended to one log + tiny index for O(1) look-ups. No database, two files, scales to millions of users; ideal for secure prototypes, IoT, and web apps.
