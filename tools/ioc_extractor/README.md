# 5. IOC extractor

Pulls IPs, domains, URLs, emails, hashes and CVE IDs out of any text or file (including defanged input), removes duplicates, defangs on request and exports CSV or JSON. Includes a Tkinter window.

Part of the [SOC Triage Toolkit](../../README.md). All sample data is fake.

## What you will learn

- What an IOC is and how analysts share them safely (defanging)
- Regex patterns and their false positives (file names that look like domains)
- Why .eml files must be decoded before extraction
- Keeping pure logic apart from a GUI

## Usage

Run these from the project root:

```bash
python -m tools.ioc_extractor sample_data/emails/02_phish_paypal_lookalike.eml --defang
python -m tools.ioc_extractor sample_data/auth.log --types ip --exclude-private --format csv
python -m tools.ioc_extractor.gui
```

## Example output

```text
$ python -m tools.ioc_extractor sample_data/emails/02_phish_paypal_lookalike.eml --defang
========================================================================
 IOC EXTRACTOR
========================================================================
Found 20 unique indicators (defanged)

+--------+-----------------------------------------------+
| type   | value                                         |
+--------+-----------------------------------------------+
| ip     | 198[.]51[.]100[.]77                           |
| ip     | 203[.]0[.]113[.]77                            |
| domain | bulk-sender[.]example                         |
| domain | login[.]paypa1-secure[.]example               |
| domain | mail-collector[.]example                      |
| domain | mail[.]paypa1-secure[.]example                |
| domain | mx[.]victim-corp[.]example                    |
| domain | paypa1-secure[.]example                       |
| domain | relay[.]bulk-sender[.]example                 |
| domain | sample[.]example                              |
...
```

## Try it yourself

- Add IPv6 extraction.
- Add a registry-style check that rejects fake TLDs.
- Highlight matches from the blocklist in the window (already supported once you load one).

## Limitations

- Code such as os.path can look like a domain.
- IPv4 only.
- The GUI window is not covered by automated tests; the logic behind it is.
