# Playbook: Suspicious login

> Short teaching playbook. Adapt it to your organisation's policy and tools.

## When to use it

Impossible travel, a login from a new country or device, or a login at an unusual time.

## Quick triage questions

1. Can the user explain it (travel, new phone, VPN)?
2. Was MFA used and satisfied?
3. Did anything unusual happen after the login (mailbox rules, downloads, new devices)?
4. Is the source IP a known VPN or hosting provider?

## Decide

- True positive: user denies it, or the travel is physically impossible without a VPN.
- False positive: confirmed through a separate channel.
- Several signals together (travel + new country + new device) deserve urgency.

## Contain

- Contact the user by phone or chat, not by replying to an email.
- If not confirmed: revoke sessions, reset the password, re-register MFA.
- Review the account's recent activity.

## Evidence to keep

- The login record with IP, country and device.
- The user's confirmation or denial and when it was given.

## Escalate when

- The account is privileged.
- Data access or mailbox changes follow the login.

## Toolkit tools that help

- login_analyzer: see which signals fired and why.
- bruteforce_detector: check for failures before the success.
- alert_prioritizer: rank it against other alerts.
