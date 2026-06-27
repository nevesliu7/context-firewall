# Security Policy

Context Firewall is a prototype enforcement gateway. Do not treat the default local configuration as production secure.

## Production Requirements

- Enable verified JWT auth.
- Replace SQLite with DynamoDB.
- Store provider credentials in Secrets Manager.
- Encrypt approval artifacts with KMS.
- Move policy packs to a governed configuration store.
- Review detectors against real internal data before live provider forwarding.

## Reporting Issues

For a portfolio repo, open a private issue or contact the repository owner. Do not include real secrets, raw customer data, or private prompts in bug reports.

