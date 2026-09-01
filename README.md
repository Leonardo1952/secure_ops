# SecureOps

SecureOps is a Flask-based security monitoring project developed for academic
AppSec practice.

## Continuous Integration

Each push or pull request to `main` runs the SecureOps CI workflow with:

- automated tests with pytest;
- static security analysis with Bandit;
- dependency vulnerability scanning with pip-audit.
