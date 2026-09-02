# SecureOps Evidence Checklist

This directory stores evidence captured manually for SecureOps v1.1. Do not add fabricated screenshots or files containing secrets, private keys, tokens, real user log content or sensitive infrastructure details.

Suggested evidence files:

- `01-login.png`: login page with SecureOps branding and protected access indication.
- `02-dashboard.png`: SOC/SIEM dashboard with KPIs, charts, security posture and recent events.
- `03-security-events.png`: Security Events page with search, filters, pagination and severity badges.
- `04-github-actions.png`: CI and Deploy to OCI green in the same GitHub Actions execution.
- `05-oci-instance.png`: Oracle Cloud instance overview without exposing private keys or sensitive metadata.
- `06-ssh-hardening.png`: SSH hardening evidence showing key-based access and disabled password authentication.
- `07-firewall.png`: firewall rules showing least-privilege exposure.
- `08-fail2ban.png`: Fail2Ban status showing active `sshd` jail and configured ban policy.
- `09-https.png`: browser or TLS evidence showing valid HTTPS for the SecureOps domain.
- `10-pqc.png`: evidence that PQC key exchange is supported.
- `11-ssl-labs.png`: SSL Labs result showing A+ grade.
- `12-health.png`: `/health` response showing `healthy` and version `1.1.0`.
- `13-nginx-telemetry.png`: dashboard or events page showing Nginx-derived events.
- `14-fail2ban-telemetry.png`: dashboard or events page showing Fail2Ban-derived events.
- `15-ssh-telemetry.png`: dashboard or events page showing SSH-derived events.
- `16-systemd-timers.png`: production timer status for the three collectors.

Before adding evidence, review screenshots for secrets, IPs that should not be disclosed, tokens, usernames that are not needed for the academic report and raw log content.
