# Product direction: self-hosted SentinelX

SentinelX is an open-source, self-hosted infrastructure monitoring and security platform. It is not a multi-tenant SaaS product.

Each operator deploys an independent central API, database and dashboard inside infrastructure they control. Linux and Windows agents send telemetry only to that operator's installation. There is no shared vendor cloud, customer organization signup, hosted tenant model or mandatory external account.

This document replaces the earlier SaaS architecture proposal. The SaaS proposal is obsolete and must not be used as the product roadmap.

See:
- [Self-hosted installation](SELF_HOSTED_INSTALLATION.md)
- [Security model](SECURITY.md)
- [Contributing](../CONTRIBUTING.md)

Current development limitations are documented in the repository README and security guide. In particular, the current shared agent token and lack of built-in dashboard authentication mean that deployments must remain private or be protected by a TLS reverse proxy and access-control layer.
