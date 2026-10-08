# Security policy

`fim` is a defensive tool, and its safety checks (read-only access to monitored files, the HMAC
baseline, the handling of hostile file names, the resource limits) are part of what it promises.
A way around them is a vulnerability.

## Reporting a vulnerability

Please report it **privately** with GitHub private vulnerability reporting: open the repository's
**Security** tab, choose **Report a vulnerability**, and describe the problem there. Do not open a
public issue or pull request for it, and do not post details anywhere public before a fix exists.

A useful report has the version (`fim --version`), the operating system and Python version, the
exact command or input, what you expected, and what happened.

This is a one-person project, so there is no guaranteed response time.

## Supported versions

The project is pre-release. Once 1.0.0 exists, only the latest release receives fixes.
