# Contributing to SentinelX

Thanks for helping improve SentinelX, an open-source, self-hosted monitoring and security project.

## Development setup

```bash
git clone https://github.com/eetemanojkumar-sys/sentinelex.git
cd sentinelex
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SENTINELX_AGENT_TOKEN="local-development-token"
export DATABASE_URL="sqlite:///./sentinelx-dev.db"
```

Run the API:

```bash
uvicorn server.main:app --reload --host 127.0.0.1 --port 8000
```

Run tests:

```bash
python -m unittest discover -s server -p 'test_*.py'
python -m unittest discover -s agent -p 'test_*.py'
```

## Contribution guidelines

- Keep the product self-hosted and open source; do not add SaaS tenancy, vendor registration or mandatory cloud dependencies.
- Prefer small, reviewable changes with tests.
- Keep Linux and Windows behavior aligned where practical.
- Do not add telemetry that leaves the operator's installation without explicit configuration and documentation.
- Never commit credentials, private data, production environment files or customer telemetry.
- Document new environment variables, API routes, database changes and upgrade requirements.
- Preserve backwards compatibility where possible and explain breaking changes.
- Run relevant tests locally and report any platform-specific test limitations.

## Pull requests

Include the problem, implementation summary, test commands/results, operating systems tested and any migration/security impact.
