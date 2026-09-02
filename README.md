# SecureOps

SecureOps is a Flask-based security monitoring and DevSecOps project developed for academic practice in Application Security, Cloud Infrastructure and Computer Security.

The project demonstrates the implementation of a small security monitoring platform combined with secure authentication, security event logging, server hardening, HTTPS, post-quantum TLS key exchange and automated CI/CD deployment.

The application is currently deployed at:

**https://secureops.leonardooliveira.dev**

---

## Project Objective

The main objective of SecureOps is to demonstrate how application security, infrastructure hardening and DevSecOps practices can be combined in a small but functional web application.

The project covers:

- secure authentication;
- protected application routes;
- security event monitoring;
- OWASP Top 10:2025 mitigations;
- cloud deployment;
- secure SSH access;
- firewall and Fail2Ban protection;
- HTTPS with Let's Encrypt;
- post-quantum TLS key exchange;
- automated testing and security analysis;
- continuous integration and continuous deployment.

---

## Features

SecureOps currently provides:

- user login;
- protected dashboard;
- logout;
- security event collection;
- security event filtering;
- event pagination;
- security overview cards;
- login success and failure monitoring;
- unauthorized access monitoring;
- rate-limit event monitoring.

The application records events such as:

- `AUTH_SUCCESS`
- `AUTH_FAILURE`
- `LOGOUT`
- `UNAUTHORIZED_ACCESS`
- `RATE_LIMIT_EXCEEDED`
- `SUSPICIOUS_PATH`
- `NGINX_403`
- `NGINX_404`
- `IP_BANNED`
- `IP_UNBANNED`

---

## Nginx Security Telemetry

SecureOps includes a one-shot Nginx collector for infrastructure security telemetry:

```bash
python scripts/nginx_collector.py
```

The collector runs outside the Flask/Gunicorn request path. The web application does not read `/var/log/nginx`, does not execute privileged commands and does not require sudo. The operating system user that runs the collector must have read access to the configured Nginx access log.

Configuration:

```text
NGINX_ACCESS_LOG=/var/log/nginx/access.log
NGINX_COLLECTOR_STATE=instance/nginx_collector_state.json
```

Detected events:

- `SUSPICIOUS_PATH` with `HIGH` severity for paths such as `/.env`, `/.git/config`, `/wp-admin`, `/phpmyadmin`, `/server-status` and `/actuator`;
- `NGINX_403` with `MEDIUM` severity;
- `NGINX_404` with `LOW` severity.

The collector stores only minimized event data: event type, severity, source IP and a short path-only description. Query strings, cookies, request bodies, full headers, referers and user agents are not stored.

Checkpointing uses inode and byte offset in `instance/nginx_collector_state.json`, which is outside Git. Each execution processes only new lines. If the log is rotated or truncated, the collector safely restarts from the beginning of the current file.

Dry-run mode validates parsing without writing events or changing the checkpoint:

```bash
python scripts/nginx_collector.py --dry-run
```

---

## Fail2Ban Security Telemetry

SecureOps also includes a one-shot Fail2Ban collector:

```bash
python scripts/fail2ban_collector.py
```

The collector is separate from Flask and Gunicorn. It reads the configured Fail2Ban log, converts relevant ban/unban actions into `SecurityEvent` records and exits. The web process does not read Fail2Ban logs, call `fail2ban-client`, execute privileged commands or require sudo.

Configuration:

```text
FAIL2BAN_LOG=/var/log/fail2ban.log
FAIL2BAN_COLLECTOR_STATE=instance/fail2ban_collector_state.json
```

Detected events:

- `IP_BANNED` with `HIGH` severity for Fail2Ban `Ban` actions;
- `IP_UNBANNED` with `INFO` severity for Fail2Ban `Unban` actions.

The collector accepts any Fail2Ban jail name, including `sshd`, `nginx-http-auth` or `recidive`. It stores only minimized event data: action type, severity, source IP and the jail name in a short description. It does not store PID, full log lines, credentials, stack traces or Fail2Ban configuration.

Checkpointing uses inode and byte offset in `instance/fail2ban_collector_state.json`, separate from the Nginx collector state. Each execution processes only new lines. If the log is rotated or truncated, the collector restarts from the beginning of the current file.

Dry-run mode validates parsing without writing events or changing the checkpoint:

```bash
python scripts/fail2ban_collector.py --dry-run
```

A future production step can run this one-shot command through a dedicated systemd service and timer after log read permissions are reviewed manually.

---

## Architecture

The production architecture follows this flow:

```text
Internet
   |
   v
Oracle Cloud Infrastructure
   |
   v
Firewall / Fail2Ban
   |
   v
Nginx 1.30.4
OpenSSL 3.5.8
TLS 1.2 / TLS 1.3
X25519MLKEM768
   |
   v
Gunicorn
127.0.0.1:8000
   |
   v
Flask
   |
   v
SQLite
