# cred-audit

Password strength and credential policy auditing that scores **real resistance
to offline cracking** — not the "one uppercase, one symbol" checkbox rules that
happily rate `Password1!` as strong.

## The problem it solves

Conventional strength meters count character classes. Attackers do not. They
run a wordlist through a mangling ruleset, and `P@ssw0rd2024` falls in the same
second as `password`. `cred-audit` models what the attacker actually does:

```
P@ssw0rd2024
  Entropy       : 78.8 bits raw / 50.8 bits effective
  Rating        : MODERATE
  Offline crack : 3 hours
  Weaknesses    :
    - contains the common word 'password' — the first thing any wordlist
      attack tries, including leet-substituted forms
    - ends with a year — a standard mangling rule
```

Seventy-nine bits on paper. Three hours in practice.

## How it scores

1. **Raw entropy** — `length x log2(alphabet size)`, the theoretical search space.
2. **Structural penalties** — bits are deducted for the patterns cracking rules
   exploit first:
   - dictionary words, including leet-substituted forms (`P@ssw0rd` -> `password`)
   - keyboard walks (`qwerty`, `asdf`)
   - sequential runs (`abc`, `123`)
   - characters repeated three or more times
   - a trailing year (`...2024`)
   - the Capitalised-word + digits + symbol shape that policies accidentally force
   - very few distinct characters
3. **Effective entropy** drives the rating and the crack-time estimate, which
   assumes an offline attack at 10^11 guesses/second against a fast hash.

## Breach corpus check (privacy preserving)

With `--check-breaches`, the password is tested against Have I Been Pwned using
**k-anonymity**: only the first five characters of its SHA-1 hash leave the
machine. The service returns every hash suffix in that bucket and the match is
made locally. The password itself is never transmitted, and the service cannot
determine which password was checked.

```
  Rating        : COMPROMISED
  Breach corpus : FOUND 584,516 times — must not be used
```

## Requirements

Python 3.10 or newer. No packages to install.
Network access is required only for `--check-breaches`.

## Usage

```bash
# Prompt for a password without echoing it to the terminal
python3 cred_audit.py

# Audit one password, including the breach corpus
python3 cred_audit.py -p 'MyPassphrase' --check-breaches

# Audit a whole file, one password per line, against a strict policy
python3 cred_audit.py -f candidates.txt --min-length 14 --classes 3 -o report.json
```

> Prefer the interactive prompt over `-p` on shared machines — arguments are
> visible in your shell history and in the process list.

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `-p`, `--password` | Password to audit | hidden prompt |
| `-f`, `--file` | Audit every password in this file | — |
| `--min-length` | Policy: minimum length | `12` |
| `--classes` | Policy: required character classes | `3` |
| `--allow-common` | Policy: permit dictionary-word based passwords | off |
| `--check-breaches` | Check Have I Been Pwned via k-anonymity | off |
| `-o`, `--output` | Write the JSON report to this file | none |

## Exit codes

`0` when every password passed policy, `1` when any failed — so it can gate a
password rotation script or a CI check over a seeded credentials file.

## License

MIT — see [LICENSE](LICENSE).
