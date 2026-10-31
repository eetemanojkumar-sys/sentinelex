# Security model and deployment guidance

SentinelX is self-hosted. The operator is responsible for protecting the central server, database, credentials, network and backups.

## Current implementation

- Telemetry ingestion requires the configured `SENTINELX_AGENT_TOKEN` in the `X-Agent-Token` request header.
- The central API supports bounded telemetry payloads and idempotent batch ingestion.
- The database is local to the installation.
- The current token is shared by agents in one installation; it is not a per-agent credential.
- Dashboard and monitoring read APIs currently have no built-in user login or role-based access control.

## Required deployment controls

1. Keep the API on loopback or a private network.
2. Put remote access behind a TLS reverse proxy and an authentication/access-control layer.
3. Restrict agent ingestion to trusted network ranges where possible.
4. Generate a high-entropy token and store it in a protected environment file or secret manager.
5. Never commit tokens, database passwords, private keys or production configuration.
6. Run the service as a dedicated unprivileged OS account.
7. Restrict database access to the central service.
8. Encrypt and regularly test database backups.
9. Apply OS and Python dependency security updates.

## Planned security work

- Local administrator bootstrap and session-based dashboard authentication.
- Per-agent enrollment tokens and unique agent credentials.
- Credential rotation and revocation.
- TLS verification and hardened agent transport defaults.
- Rate limiting and audit logging.
- Database migrations and documented upgrade/backup procedures.
- Security tests for authorization and enrollment.

## Reporting a vulnerability

Do not publish exploitable vulnerability details in a public issue. Contact the repository maintainers privately through the GitHub repository's security reporting mechanism when it is enabled, or request a private disclosure channel from the maintainers.
