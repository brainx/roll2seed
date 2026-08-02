# Entropy, dice, and Bitcoin recovery phrases

This guide explains why entropy is the foundation of a recovery phrase, what Roll2Seed does to preserve it, and what the tool cannot guarantee. Read it before generating a phrase that may control real funds.

## What entropy means here

Entropy measures uncertainty before a secret is observed. An ideal 128-bit value has `2^128` equally likely possibilities. In min-entropy terms, no one candidate should be more likely than `2^-128`.

That uncertainty is what makes exhaustive guessing infeasible. The word "random" is not enough: a process can look irregular while still being predictable to someone who knows how it was produced. Human choices, familiar patterns, software with a weak random-number source, a loaded die, or a recorded generation session can all reduce the real uncertainty.

The security of a deterministic wallet cannot exceed the unpredictability and secrecy of its starting material. Once a BIP39 mnemonic is known, compatible wallets can deterministically recreate the same seed and keys. The complete ordered dice sequence can recreate the mnemonic, so it is secret material too.

## Why weak entropy cannot be repaired later

A cryptographic hash can map input to a uniformly shaped output, but it cannot manufacture choices that never existed. If a person chooses from one million plausible patterns and hashes the choice, an attacker still has only about one million candidates to test.

The same principle applies to BIP39's SHA-256 checksum. The checksum helps reject many mistyped or invalid phrases. It is computed from the entropy, so it adds no independent secret bits and is not a substitute for a strong entropy source.

Encryption, a strong wallet implementation, and secure hardware remain important, but none of them retroactively make a guessable recovery phrase unguessable.

## How much entropy a d6 provides

One ideal, independent roll of a fair six-sided die has six equally likely outcomes and contributes:

```text
log2(6) = 2.5849625007... bits
```

BIP39 permits 128, 160, 192, 224, or 256 initial entropy bits. It appends `ENT / 32` checksum bits and splits the result into 11-bit word indexes.

| BIP39 words | Initial entropy | Checksum | Minimum fair-d6 rolls |
| ---: | ---: | ---: | ---: |
| 12 | 128 bits | 4 bits | 50 |
| 15 | 160 bits | 5 bits | 62 |
| 18 | 192 bits | 6 bits | 75 |
| 21 | 224 bits | 7 bits | 87 |
| 24 | 256 bits | 8 bits | 100 |

The roll counts are minimums, calculated from `ceil(ENT / log2(6))`. They assume each accepted physical result is independent and uniformly distributed. A short run of results cannot establish that a particular die is fair.

## Why direct conversion can be biased

Six-sided dice produce a number of possible sequences equal to a power of six. BIP39 entropy needs a power-of-two number of equally likely outcomes. Those ranges do not divide evenly, so simply taking a base-6 number modulo `2^ENT` makes some outputs more likely than others.

Roll2Seed maintains a uniform `(value, range)` state. When the range is large enough, it accepts only the largest prefix whose size is an exact multiple of the target range. If a roll sequence lands in the leftover tail, that tail remains uniform; the sampler recycles it with the next roll. The app therefore sometimes asks for more than the table's minimum, but never uses unrestricted modulo reduction.

This gives an exactly uniform target value if the physical rolls are themselves independent and fair and the entered sequence is accurate. It does not turn biased or chosen inputs into a trustworthy entropy source.

## Safe operating checklist

Before starting:

- Use a trusted device, operating system, browser, and reviewed copy of the application.
- Prefer the hardened local server on `127.0.0.1`; localhost prevents network transport but does not defend against malware, browser extensions, screen capture, or a compromised build.
- Work in a private physical space without cameras, microphones, screen sharing, remote administration, or observers.
- Use one ordinary, opaque, well-formed d6 on a stable hard surface.
- Decide in advance how to handle a die that is cocked or leaves the rolling area. Never selectively reroll a valid face, including repeats or long runs that look suspicious.
- Prepare a private paper tally. Do not put rolls or words in notes apps, photos, cloud storage, chat, email, password managers, clipboard history, printers, or online validation sites.

During generation:

- Enter every valid roll exactly once and in order.
- Do not choose outcomes, discard patterns, alternate dice based on prior results, or stop early.
- Treat the full tally as equivalent to the final mnemonic.
- If you discover a transcription error, correct only the recorded face that was actually rolled. The app invalidates and recomputes the derived phrase.

After generation:

- Record the mnemonic using a durable backup method appropriate to the amount at risk.
- Verify spelling, order, and the selected word count without exposing the phrase to another device or service.
- Test a complete restore in the exact wallet family you intend to use before funding it. A checksum or spot-check is not a recovery test.
- Erase the browser session, then destroy the dice tally after the verified backup is complete.
- Store backups against theft, fire, water, accidental disposal, and unauthorized photography. Avoid keeping all copies in one place.

## Choosing a phrase length

More words encode more initial entropy, but also create a longer secret to transcribe and protect. The chosen length must be supported by the wallet that will restore it. Roll2Seed supports all BIP39-defined lengths but does not decide which is appropriate for a particular wallet or risk level.

The phrase length is only one part of wallet security. Device compromise, malicious wallet software, exposed backups, coercion, incorrect restoration, and loss can dominate the brute-force margin of the mnemonic itself.

## BIP39 passphrases are separate

BIP39 optionally combines a mnemonic with a passphrase when deriving a wallet seed. Every passphrase produces a valid-looking wallet, and an incorrect or forgotten passphrase produces a different wallet. Roll2Seed intentionally does not create, store, or validate passphrases.

Do not confuse a BIP39 passphrase with the mnemonic's checksum or with additional dice entropy. Before using one, understand the target wallet's exact backup and recovery behavior and test it completely.

## What Roll2Seed does not prove

Roll2Seed does not prove that:

- a die is fair or rolls are independent;
- the entered faces match the physical results;
- the local source code, build, browser, extensions, operating system, firmware, display, or room is trustworthy;
- JavaScript memory has been forensically erased;
- a wallet correctly supports BIP39 or the selected phrase length;
- a backup can survive loss, damage, theft, or user error;
- the application has received an independent professional security audit.

The app's rejection sampler addresses conversion bias. Its local-only design and lifecycle controls reduce some exposure paths. Neither is a complete wallet-security guarantee.

## Primary references

- [BIP39 specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) — entropy sizes, checksum construction, word mapping, and mnemonic-to-seed behavior.
- [Official BIP39 English wordlist](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt) — the 2,048-word list embedded by this project.
- [NIST SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final) — entropy-source design, validation, and health-testing concepts.
- [NIST IR 8427](https://csrc.nist.gov/pubs/ir/8427/final) — unpredictability, min-entropy, and the full-entropy assumption.
- [Web Cryptography API](https://www.w3.org/TR/webcrypto/) — the browser SHA-256 interface used for the BIP39 checksum and wordlist self-check.
