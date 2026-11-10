# Playbook: Suspected phishing email

> Short teaching playbook. Adapt it to your organisation's policy and tools.

## When to use it

A user reports a suspicious email, or the mail gateway flags one.

## Quick triage questions

1. Who received it and who clicked, replied or opened an attachment?
2. Do SPF, DKIM and DMARC pass, and do they line up with the From address?
3. Do From, Reply-To and Return-Path point to the same organisation?
4. Does any link go somewhere different from its text, or to a look-alike domain or raw IP?
5. Is the attachment an executable, macro document or double extension?

## Decide

- True positive: failed authentication plus impersonation, a bad link or a dangerous attachment.
- False positive: authenticated bulk mail from a known sender with matching links.
- Unsure: treat as a true positive until proven otherwise.

## Contain

- Quarantine or delete the message from every mailbox.
- Block the sender domain and malicious URLs at the gateway and proxy.
- Reset passwords and revoke sessions for anyone who entered credentials.

## Evidence to keep

- The original .eml with full headers.
- Hashes of attachments.
- List of recipients and who interacted.

## Escalate when

- Anyone entered credentials or opened an attachment.
- The target was an executive or finance team (possible business email compromise).

## Toolkit tools that help

- phishing_analyzer: score the .eml and read the reasons.
- ioc_extractor and intel_matcher: pull out links and check them against your blocklist.
- report_generator: record the verdict.
