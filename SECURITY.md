# Security policy

Roll2Seed handles material that can control Bitcoin funds. Treat security reports and reproductions accordingly.

## Supported versions

Only the latest tagged release is supported with security fixes. The current supported release line is `0.1.x`.

## Private reporting

Use a private GitHub Security Advisory for this repository when that option is available. If private vulnerability reporting is unavailable, contact the repository owner through an established private channel before disclosing details publicly.

Never include a real mnemonic, dice-roll sequence, private key, address balance, wallet file, personal information, or other live secret in a report. Use synthetic test vectors that control no funds.

Include:

- the affected release or commit;
- the impact and realistic attack conditions;
- minimal reproduction steps using synthetic data;
- relevant browser, operating-system, and Node.js versions;
- a proposed mitigation, if known.

Security-sensitive areas include sampling bias, BIP39 conversion, wordlist integrity, stale asynchronous state, secret reveal and correction paths, lifecycle cleanup, browser persistence, network requests, security headers, and accidental non-loopback exposure.

## Scope and limitations

The project has no bug-bounty program and makes no reward commitment. Reports about a biased or malicious physical die, compromised endpoint, malicious browser extension, infected operating system, physical surveillance, or forensic recovery from JavaScript-managed memory may describe real risks, but those risks are outside the protections the application can guarantee.

Do not test against a wallet containing funds or publish a proof of concept that exposes another person's secret material.
