# SentinelX security model

SentinelX is self-hosted. The operator controls the central service, database, administrator account, network and backups.

## Administrator authentication

- Configure `SENTINELX_ADMIN_USERNAME` and `SENTINELX_ADMIN_PASSWORD` before first startup.
- The first startup creates a local administrator record with a salted PBKDF2-SHA256 password hash. The plaintext password is not stored.
- The dashboard and monitoring/admin APIs require an authenticated administrator session.
- Session identifiers are random, stored as SHA-256 digests, HttpOnly, SameSite=Strict, and Secure by default.
- Set `SENTINELX_COOKIE_SECURE=false` only for isolated local HTTP development. Remote access must use HTTPS.
- Set `SENTINELX_RESET_ADMIN_PASSWORD=true` for one startup to rotate the configured administrator password, then remove that flag.
- Protect the environment file and database. There is no public registration or hosted account service.

## Per-agent enrollment and revocation

1. An administrator signs in and creates a short-lived one-time enrollment token through `POST /api/v1/admin/agents/enrollment-tokens`.
2. The agent exchanges it at `POST /api/v1/agents/enroll` with its unique host ID.
3. The central service marks the enrollment token as used and returns a random credential bound to that host.
4. The agent stores its credential in its local SentinelX credential directory; POSIX systems use mode 0600.
5. Telemetry must present the credential in `X-Agent-Token`; the server checks the credential, host binding and revocation state.
6. Administrators can list enrolled agents and revoke a credential. Revocation takes effect on the next telemetry request.

The shared legacy token is disabled unless `SENTINELX_ALLOW_LEGACY_AGENT_TOKEN=true` is explicitly enabled. Do not enable it for normal operation.

## Deployment requirements

- Keep the central API on loopback or a private network.
- Use a TLS reverse proxy for remote access; never expose development Uvicorn directly to the public internet.
- Restrict agent ingestion to trusted networks where practical.
- Run the service as an unprivileged OS account.
- Keep environment files and agent credential files readable only by the service/operator account.
- Back up the database and test restoration.
- Apply operating-system and Python dependency updates.

## Current limitations

The current release provides one local administrator account, not multi-user RBAC or MFA. Session login throttling and a full audit trail are not yet implemented. Protect administrator access with a private network or reverse proxy rate limiting. The Windows agent credential file relies on the permissions of the Windows account/profile directory; production installers should set an explicit restrictive ACL.

## Vulnerability reporting

Do not publish exploitable vulnerability details in a public issue. Use the repository's private security reporting channel when enabled.
