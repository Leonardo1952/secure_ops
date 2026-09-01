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