# Changelog

All notable changes to Sentinelle.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

Nothing yet.

## [0.2.1] — 2026-08-31

### Fixed
- PHP constraint lowered to `>=8.1`. Nothing in the code required 8.2, and
  Symfony 6.4 runs on 8.1: asking for more excluded projects for no reason.
- `branch-alias` aligned on `0.2.x-dev`.

## [0.2.0] — 2026-08-31

### Added
- **Dry-run mode** (`essai: true`): Sentinelle detects, logs and alerts, but
  blocks nothing. Every avoided block is logged along with what would have been
  decided, duration included.

  > *A mechanism you cannot try without risk will not be tried — it will be
  > installed and switched off at the first incident.*

- **`sentinelle:verifier` command**: checks that the cache answers, that both
  tables exist, that the allowlist is not empty and that alerts have a valid
  recipient.

  Each of these is a way the mechanism can fail **silently** — without a cache,
  counters always return zero, no threshold ever fires, and detection is
  disarmed without anything saying so.

- `CHANGELOG.md` and `CONTRIBUTING.md`.
- Dashboard screenshot in both READMEs.

### Changed
- **Symfony 8** compatibility.
- English README by default, French in `README.fr.md`. *Packagist displays
  `README.md`, and the PHP ecosystem is English-speaking.*
- Both README hooks aligned on the package description.

## [0.1.2] — 2026-08-31

### Fixed
- An import left on the old namespace after extraction, causing a
  `ClassNotFoundError` on every request — and not a single line logged.
- The whole body of the logger is now protected, not just the write. On
  `kernel.terminate` the response has already been sent: an exception went
  nowhere, the site answered 200 and the table stayed empty.

  > *A logger that can fail silently is worse than no logger at all: you believe
  > it is running.*

- The controller no longer extends `AbstractController`, which expects a
  restricted container built by autoconfiguration — a mechanism disabled in a
  bundle where everything is declared by hand. Dependencies are now injected
  explicitly.
- Journal filter: `tout` and `all` meant the same thing without knowing about
  each other, a leftover from a partial translation.
- The matched pattern and the query string are shown in the journal. Without
  them, two exploitation attempts appeared as two identical rows.

## [0.1.1] — 2026-08-31

### Fixed
- `getPath()`: without it, `@SentinelleBundle/config/…` pointed at
  `src/config/`, and neither routes nor services would load.

## [0.1.0] — 2026-08-31

First release, extracted from an application running in production.

### Fixed before release
- `Bundle` instead of `AbstractBundle`: the latter carries its own configuration
  and **silently ignores** any extension class written alongside it. The bundle
  loaded perfectly, with an empty configuration tree.

### Features
- Logs every request on `kernel.terminate`, after the response has been sent —
  which is also the only moment the status code is known.
- Detection: code execution, SQL injection, directory traversal, Log4Shell,
  deserialisation; probes; brute force.
- Progressive blocking: 24 hours, 7 days, then permanent. Blocks expire, and
  that is deliberate — most scanning addresses are compromised machines or
  recycled cloud addresses.
- **Refuses to block a critical provider**, automatically and manually,
  recognised by reverse DNS.
- Email alert, at most one per address per hour.
- Dashboard showing each address's owner.
- `sentinelle:purger` command, without which strike counters never reset.