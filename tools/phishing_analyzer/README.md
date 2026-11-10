# 4. Phishing email analyzer

Parses .eml files: From, Reply-To, Return-Path, the Received chain, SPF/DKIM/DMARC results, links and attachments, then gives a 0-100 risk score where every point has a reason.

Part of the [SOC Triage Toolkit](../../README.md). All sample data is fake.

## What you will learn

- What SPF, DKIM and DMARC each prove
- Why Reply-To and Return-Path mismatches matter
- Look-alike domains, display-name spoofing and link/text mismatches
- Reading the Received chain from the oldest hop to find the true origin
- Why passing authentication does NOT prove an email is safe

## Usage

Run these from the project root:

```bash
python -m tools.phishing_analyzer sample_data/emails/02_phish_paypal_lookalike.eml
python -m tools.phishing_analyzer sample_data/emails --json analysis.json
```

## Example output

```text
$ python -m tools.phishing_analyzer sample_data/emails/02_phish_paypal_lookalike.eml
========================================================================
 EMAIL: 02_phish_paypal_lookalike.eml
========================================================================
From     : PayPal Security <service@paypa1-secure.example>
Reply-To : helpdesk-paypal@mail-collector.example
Return   : <bounce@bulk-sender.example>
Subject  : URGENT: Your account has been suspended - verify within 24 hours
Auth     : SPF=FAIL  DKIM=NONE  DMARC=FAIL
...
Why this score:
  +30  Sender domain paypa1-secure.example: 'paypal' embedded in unrelated domain 'paypa1-secure.example'.
  +25  SPF check FAILED - the receiving server could not verify the sender.
  +25  DMARC check FAILED - the receiving server could not verify the sender.
  +25  Display name claims to be 'paypal' but the mail comes from paypa1-secure.example.
  +25  Link: link text shows one site but the link goes to another (e.g. http://198.51.100.77/verify).
  +20  Reply-To (mail-collector.example) differs from From (paypa1-secure.example): replies would go to someone other than the apparent sender.
  +20  Link: link goes to a look-alike domain (e.g. http://login.paypa1-secure.example/verify).
  +20  Link: link points to a raw IP address (e.g. http://198.51.100.77/verify).
  +18  Pressure language in the subject: 'urgent', 'account has been suspended', 'within 24 hours'.
  +10  Return-Path domain (bulk-sender.example) differs from From domain (often benign for bulk senders, suspicious here).
  +8   DKIM result is 'none' - no proof of who sent this.
```

## Try it yourself

- Add your organisation's domains to the brand list in soc_common/domains.py.
- Add a check for a brand-new sending domain using the intel matcher's online mode.
- Score HTML emails with hidden text.

## Limitations

- Header analysis only: it never opens links or runs attachments.
- Authentication results are trusted as written by your mail server.
- The brand list is small and the scoring weights are judgement calls.
