# Playbook: Brute force or password spraying

> Short teaching playbook. Adapt it to your organisation's policy and tools.

## When to use it

Many failed logins from one IP, many accounts from one IP, or one account failing from many IPs.

## Quick triage questions

1. Did any login succeed from the attacking IP afterwards?
2. Is the target internet-facing, and which accounts were tried?
3. Were non-existent usernames used (wordlist guessing)?
4. Is the source IP already on a blocklist?

## Decide

- True positive: sustained failures from an external source.
- False positive: one user mistyping, or a monitoring tool with a stale password.
- Success after failures is treated as a compromise until the account owner confirms.

## Contain

- Block the attacking IP(s).
- If a login succeeded: disable the account, reset credentials, kill sessions, review commands and new accounts.
- Enforce MFA and lockout; prefer SSH keys over passwords.

## Evidence to keep

- Relevant auth and web log lines.
- The first and last failed attempt times and the success time.
- Commands run after the login.

## Escalate when

- A success followed the failures.
- Privileged or service accounts were involved.
- There are signs of persistence (new users, cron jobs, web shells).

## Toolkit tools that help

- bruteforce_detector: find the pattern and the success.
- timeline_builder: see what the attacker did next.
- attack_mapper: T1110 and sub-techniques.
