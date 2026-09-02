# SecureOps Architecture

## Overview

SecureOps v1.1 runs as a Flask application behind Nginx and Gunicorn on an Oracle Cloud Ubuntu Server 24.04 VM. It stores security telemetry in SQLite through the `SecurityEvent` model.

The application presents a protected SOC/SIEM-style dashboard and a protected Security Events page. Infrastructure telemetry is collected by separate one-shot collectors for Nginx, Fail2Ban and SSH.

## Runtime Flow

```mermaid
flowchart TD
    user["User / Internet"] --> firewall["Firewall"]
    firewall --> nginx["Nginx HTTPS Reverse Proxy"]
    nginx --> gunicorn["Gunicorn on 127.0.0.1:8000"]
    gunicorn --> flask["Flask Application"]
    flask --> db[("SQLite / SecurityEvent")]
    db --> dashboard["Dashboard and Events"]
```

## Telemetry Flow

```mermaid
flowchart TD
    nginx["Nginx"] --> nginxLog["Nginx access.log"]
    nginxLog --> nginxCollector["Nginx Collector"]

    fail2banLog["Fail2Ban log"] --> fail2banCollector["Fail2Ban Collector"]
    authLog["auth.log"] --> sshCollector["SSH Collector"]

    nginxCollector --> db[("SQLite / SecurityEvent")]
    fail2banCollector --> db
    sshCollector --> db

    db --> dashboard["Dashboard"]
    db --> events["Security Events"]
```

## Collector Separation

Collectors are separate from Flask and Gunicorn:

- they run as one-shot commands;
- they process only new log lines through inode and offset checkpoints;
- they support log rotation and truncation;
- they support `--dry-run`;
- they do not run inside a Flask request;
- they do not give log-reading privileges to Gunicorn;
- they do not use `sudo` or privileged shell commands from Python.

Production uses separate systemd timers for each collector. These timers are configured on the VM and are not provisioned automatically by this repository.

## Trust Boundaries

- Nginx is the trusted reverse proxy in front of Flask.
- Flask trusts one proxy through Werkzeug `ProxyFix`.
- Public traffic reaches Flask only through Nginx.
- Infrastructure logs are consumed by collectors, not by the web process.
- Collector output is minimized before becoming `SecurityEvent` data.
- GitHub Actions uses repository secrets for deployment; secret values are not stored in Git.

## CI/CD Flow

```mermaid
flowchart TD
    change["Push or Pull Request"] --> tests["pytest"]
    tests --> bandit["Bandit"]
    bandit --> audit["pip-audit"]
    audit --> approved{"main branch?"}
    approved -->|yes| deploy["Deploy to Oracle Cloud"]
    approved -->|no| done["CI complete"]
    deploy --> pull["git pull --ff-only"]
    pull --> deps["pip install"]
    deps --> restart["Restart SecureOps"]
    restart --> internalHealth["Internal health check"]
    internalHealth --> publicHealth["Public health check"]
```

## Event Model

`SecurityEvent` stores:

- event type;
- severity;
- source IP;
- minimized description;
- creation timestamp.

The current schema intentionally avoids storing raw logs, request bodies, cookies, credentials, SSH fingerprints or full infrastructure configuration.
