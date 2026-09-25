# Coding Guidelines

Applies to the entire ez-php project — framework core, all modules, and the application template.

---

## Environment

- PHP **8.5**, Composer for dependency management
- All project based commands run **inside Docker** — never directly on the host

```
docker compose exec app <command>
```

Container name: `ez-php-app`, service name: `app`.

---

## Quality Suite

Run after every change:

```
docker compose exec app composer full
```

Executes in order:
1. `sync_guidelines.php --check` — fails if any `CLAUDE.md` has drifted from this file
2. `check_test_classes.php` — fails on a duplicate test class name (all packages share the `Tests\` namespace, so a collision is a fatal error in the aggregated run, not a test failure)
3. `phpstan analyse` — static analysis, level 9, config: `phpstan.neon`
4. `php-cs-fixer fix` — auto-fixes style (`@PSR12` + `@PHP83Migration` + strict rules)
   *(Note: `@PHP85Migration` does not exist yet in php-cs-fixer; `@PHP83Migration` is the highest available and is used intentionally even though the project targets PHP 8.5)*
5. `phpunit` — all tests with coverage

Individual commands when needed:
```
composer analyse             # PHPStan only
composer cs                  # CS Fixer only
composer test                # PHPUnit only
composer guidelines:check    # CLAUDE.md drift only
composer test-classes:check  # duplicate test class names only
```

**PHPStan:** never suppress with `@phpstan-ignore-line` — always fix the root cause.

---

## Coding Standards

- `declare(strict_types=1)` at the top of every PHP file
- Typed properties, parameters, and return values — avoid `mixed`
- PHPDoc on every class and public method
- One responsibility per class — keep classes small and focused
- Constructor injection — no service locator pattern
- No global state unless intentional and documented
- Concrete classes are `final` — extend behavior through composition, not inheritance. Exception-hierarchy base classes (e.g. `EzPhpException`, `HttpException`, `CacheException`) are one carve-out, since they exist specifically to be extended. A documented template-method-style base class (e.g. `Mailable`, meant to be configured via constructor-time subclassing) is the other — the owning module's `CLAUDE.md` must record it under Design Decisions.

**Naming:**

| Thing | Convention |
|---|---|
| Classes / Interfaces | `PascalCase` |
| Methods / variables | `camelCase` |
| Constants | `UPPER_CASE` |
| Files | Match class name exactly |

**Principles:** SOLID · KISS · DRY · YAGNI

---

## Workflow & Behavior

- Write tests **before or alongside** production code (test-first)
- Read and understand the relevant code before making any changes
- Modify the minimal number of files necessary
- Keep implementations small — if it feels big, it likely belongs in a separate module
- No hidden magic — everything must be explicit and traceable
- No large abstractions without clear necessity
- No heavy dependencies — check if PHP stdlib suffices first
- Respect module boundaries — don't reach across packages
- Keep the framework core small — what belongs in a module stays there
- Document architectural reasoning for non-obvious design decisions
- Do not change public APIs unless necessary
- Prefer composition over inheritance — no premature abstractions

---

## New Modules & CLAUDE.md Files

### 1 — Required files

Every module under `modules/<name>/` must have:

| File | Purpose |
|---|---|
| `composer.json` | package definition, deps, autoload |
| `phpstan.neon` | static analysis config, level 9 |
| `phpunit.xml` | test suite config |
| `.php-cs-fixer.php` | code style config |
| `.gitignore` | ignore `vendor/`, `.env`, cache |
| `.env.example` | environment variable defaults (copy to `.env` on first run) |
| `docker-compose.yml` | Docker Compose service definition (always `container_name: ez-php-<name>-app`) |
| `docker/app/Dockerfile` | module Docker image (`FROM au9500/php:8.5`) |
| `docker/app/container-start.sh` | container entrypoint: `composer install` → `sleep infinity` |
| `docker/app/php.ini` | PHP ini overrides (`memory_limit`, `display_errors`, `xdebug.mode`) |
| `.github/workflows/ci.yml` | standalone CI pipeline |
| `README.md` | public documentation |
| `tests/TestCase.php` | base test case for the module |
| `start.sh` | convenience script: copy `.env`, bring up Docker, wait for services, exec shell |
| `CLAUDE.md` | see section 2 below |

### 2 — CLAUDE.md structure

Every module `CLAUDE.md` must follow this exact structure:

1. **Full content of `CODING_GUIDELINES.md`, verbatim** — copy it as-is, do not summarize or shorten
2. A `---` separator
3. `# Package: ez-php/<name>` (or `# Directory: <name>` for non-package directories)
4. Module-specific section covering:
   - Source structure — file tree with one-line description per file
   - Key classes and their responsibilities
   - Design decisions and constraints
   - Testing approach and infrastructure requirements (MySQL, Redis, etc.)
   - What does **not** belong in this module

**Do not edit part 1 by hand.** It is generated from `CODING_GUIDELINES.md` by
`sync_guidelines.php` at the project root:

```
php sync_guidelines.php            # rewrite every out-of-sync CLAUDE.md
php sync_guidelines.php --check    # report drift, exit 1 if any (CI / pre-commit)
```

Edit `CODING_GUIDELINES.md`, then run the script — it replaces everything before the
`# Package:` / `# Directory:` / `# Project:` heading and preserves the hand-written
section below it byte-for-byte. Editing a single copy only creates drift; before this
script existed, all 40 copies had diverged.

### 3 — Scaffolding a new module

`make_module.php` at the project root writes the required-file set and the monorepo
wiring in one step, wrapping `docker-init` for the Docker subset:

```
composer module:make <name> -- --description="..."
php make_module.php <name> --description="..." --services=mysql,redis
```

`<name>` is the kebab-case package name; the namespace is derived as
`EzPhp\<PascalCase>` unless `--namespace=` overrides it (`bignum` → `BigNum`,
`opcache` → `OPCache`, and `dotenv` → `Env` are existing exceptions the guess
gets wrong; `websocket-client` → `WebsocketClient`, `websocket-tls` → `WebsocketTls`,
`webauthn-metadata` → `WebauthnMetadata` and `metrics-statsd` → `MetricsStatsd` are
intentional lower-case-word namespaces, and `testing-application` shares `EzPhp\Testing\`
with `testing`).

To bring in a module whose code already lives in its own repository instead of
generating a fresh skeleton, pass `--repo=` with a git URL:

```
php make_module.php <name> --repo=<git-url> [--namespace=Foo]
```

This runs `git submodule add <url> modules/<name>` instead of writing package
files, then applies the same monorepo wiring below. It is mutually exclusive
with `--services` and `--description` — a submodule brings its own Docker
scaffold (if any) and its own `composer.json` description. A minimal `CLAUDE.md`
stub is written only if the submodule doesn't already ship one, so
`composer guidelines:sync` has a `# Package:` heading to anchor part 1 against.

It writes `modules/<name>/` and registers the module in the four places the monorepo
needs it — root `composer.json` (`autoload.psr-4`), `phpstan.neon`, `phpunit.xml`
(test suite **and** coverage source), and `packages.sh` (alphabetical position).

Two things stay manual on purpose:

- **`CLAUDE.md` part 1** — only the `# Package:` section is generated. Run
  `composer guidelines:sync` afterwards; baking a guidelines copy into the generator
  would recreate the drift the sync script exists to prevent.
- **The host-port table below** (`--services` only) — editing it marks every
  `CLAUDE.md` copy as drifted at once, so the next `composer full` would fail for
  a brand-new module. The generator prints which ports to claim instead.

### 4 — Docker scaffold

Run from the new module root (requires `"ez-php/docker": "^2.0"` in `require-dev`):

```
vendor/bin/docker-init
```

This copies `Dockerfile`, `docker-compose.yml`, `.env.example`, `start.sh`, and `docker/` into the module, replacing `{{MODULE_NAME}}` placeholders. Existing files are never overwritten.

Pass `--services` to merge MySQL/Redis/Meilisearch service definitions directly into `docker-compose.yml` and uncomment the matching sections in `.env.example`, instead of adapting them by hand afterward:

```
vendor/bin/docker-init --services=mysql
vendor/bin/docker-init --services=redis
vendor/bin/docker-init --services=meilisearch
vendor/bin/docker-init --services=mysql,redis
```

Pass `--extensions` to merge PHP extension install blocks (apt packages plus `docker-php-ext-install`/`pecl` lines) directly into `docker/app/Dockerfile`, instead of hand-editing it afterward — supported extensions: `bcmath`, `gmp`, `gd`, `imagick`:

```
vendor/bin/docker-init --extensions=gmp,bcmath
vendor/bin/docker-init --extensions=gd,imagick
```

When run from a module directory inside this monorepo, any requested extension not already present is also merged into the shared root `docker/app/Dockerfile` — the container `composer full` at the root actually runs against, distinct from the module's own standalone image.

After scaffolding:

1. Adapt `docker-compose.yml` — add or remove services (MySQL, Redis, Meilisearch) as needed
2. Adapt `.env.example` — fill in connection defaults matching the services above
3. Assign a unique host port for each exposed service (see table below)

**Allocated host ports:**

| Package | `DB_HOST_PORT` (MySQL) | Redis host port | `MEILISEARCH_PORT` |
|---|---|---|---|
| root (`ez-php-project`) | 3306 | 6379 (`REDIS_PORT`) | 7700 |
| `ez-php/framework` | 3307 | — | — |
| `ez-php/` (application template) | 3308 | 6383 (`REDIS_PORT`) | — |
| `ez-php/orm` | 3309 | — | — |
| `ez-php/cache` | — | 6380 (`REDIS_HOST_PORT`) | — |
| `ez-php/queue` | 3310 | 6381 (`REDIS_HOST_PORT`) | — |
| `ez-php/rate-limiter` | — | 6382 (`REDIS_HOST_PORT`) | — |
| `ez-php/search` | — | — | 7701 |
| `ez-php/event-store` | 3311 | — | — |
| **next free** | **3312** | **6384** | **7702** |

Only set a port for services the module actually uses. Modules without external services need no port config.

> The `MEILISEARCH_PORT` column is the **host** port. Inside a Compose network the service is always reachable at `http://meilisearch:7700` regardless of the host mapping — only publish-side ports need to be unique.

> The "Redis host port" column is likewise the **host**-published port. `ez-php/cache`, `ez-php/queue`, and `ez-php/rate-limiter` map it through a separate `REDIS_HOST_PORT` env var in `docker-compose.yml`, keeping `REDIS_PORT` fixed at `6379` for in-container connections (the app container always reaches Redis at `redis:6379` over the Compose network, regardless of the host mapping) — the root project and the `ez-php/` application template are the two exceptions, since both have no host/container split and use `REDIS_PORT` for both (the template's other in-container Redis settings — `CACHE_REDIS_PORT`, `QUEUE_REDIS_PORT`, `RATE_LIMITER_REDIS_PORT` — stay fixed at `6379` regardless, same as every other module).

> This table tracks only MySQL, Redis, and Meilisearch ports — the three services shared across multiple modules where a collision is otherwise easy to introduce. Mailpit is the one other service with published host ports: SMTP `1025` and web UI `8025`. `ez-php/mail` maps them through `MAILPIT_SMTP_HOST_PORT`/`MAILPIT_API_HOST_PORT` in `modules/mail/docker-compose.yml` (mirroring the `*_HOST_PORT` pattern above, documented in `modules/mail/.env.example`); the root project and the `ez-php/` template each run their own Mailpit on the same defaults (`MAIL_PORT`/`MAIL_WEB_PORT`), so **these three stacks cannot run at the same time** without overriding those variables. It isn't a table column because no module beyond those three runs Mailpit — but a new module adding its own single-use service's ports should likewise parameterize them and document the defaults in its own `.env.example` rather than adding a column here.

### 5 — Monorepo scripts

`packages.sh` at the project root is the **central package registry**. Both `push_all.sh` and `update_all.sh` source it — the package list lives in exactly one place.

When adding a new module, add `"$ROOT/modules/<name>"` to the `PACKAGES` array in `packages.sh` in **alphabetical order** among the other `modules/*` entries (before `framework`, `ez-php`, and the root entry at the end).

---

# Package: ez-php/webauthn

WebAuthn / FIDO2 passkey authentication: registration and assertion
ceremonies, attestation verification, challenge handling.

> This file is the module-specific half. The coding guidelines above it are
> generated by `sync_guidelines.php` — run `composer guidelines:sync` from the
> monorepo root to fill them in. Never edit that part by hand.

---

## Source Structure

```
src/
├── RelyingParty.php                       — RP id/name/allowed-origins value object
├── Challenge.php                          — single-use challenge value object
├── ChallengeStoreInterface.php            — app-implemented challenge storage
├── PublicKeyCredentialSource.php          — stored credential value object
├── CredentialRepositoryInterface.php      — app-implemented credential storage
├── ClientDataValidator.php                — shared clientDataJSON type/challenge/origin check
├── AuthenticatorData.php                  — parses authenticatorData (flags, counter, AAGUID, credential data)
├── RegistrationCeremony.php               — orchestrates registration verification
├── AssertionCeremony.php                  — orchestrates assertion verification
├── SecondFactorAssertionVerifier.php      — wraps AssertionCeremony to report EzPhp\Contracts\SecondFactorResult
├── Cbor/
│   └── CborDecoder.php                    — internal minimal CBOR decoder (WebAuthn-scoped, not general-purpose)
├── Cose/
│   ├── CoseKey.php                        — parses a COSE_Key CBOR map; PEM-encodes EC/RSA keys
│   ├── SignatureVerifierInterface.php     — one implementation per COSE algorithm
│   └── Verifier/
│       ├── Es256Verifier.php              — COSE -7 (ECDSA P-256/SHA-256)
│       ├── Rs256Verifier.php              — COSE -257 (RSASSA-PKCS1-v1_5/SHA-256)
│       └── EdDsaVerifier.php              — COSE -8 (Ed25519, via libsodium)
├── Tpm/
│   ├── TpmtPublicParser.php                — parses a TPMT_PUBLIC blob (pubArea): RSA/ECC + TPM_ALG_NULL sub-fields
│   ├── TpmtPublicKey.php                   — parsed TPMT_PUBLIC result value object (keyType + RSA or EC fields)
│   ├── TpmsAttestParser.php                — parses a TPMS_ATTEST blob (certInfo), TPM_ST_ATTEST_CERTIFY arm only
│   └── TpmsAttest.php                      — parsed TPMS_ATTEST result value object
├── Asn1/
│   └── Asn1Reader.php                      — minimal DER tag-length-value/SEQUENCE reader for one X.509 extraction pattern
├── AttestationStatement/
│   ├── AttestationStatement.php           — fmt + attStmt value object
│   ├── AttestationResult.php              — verifier outcome value object
│   ├── AttestationStatementVerifierInterface.php
│   ├── AttestationStatementVerifierRegistry.php  — dispatches by fmt
│   ├── NoneAttestationVerifier.php        — "none" format
│   ├── PackedAttestationVerifier.php      — "packed" format (self + full/x5c)
│   ├── FidoU2fAttestationVerifier.php     — "fido-u2f" format
│   ├── TpmAttestationVerifier.php         — "tpm" format (WebAuthn §8.3), TPMT_PUBLIC/TPMS_ATTEST-backed
│   ├── AndroidKeyAttestationVerifier.php  — "android-key" format (WebAuthn §8.4), key attestation extension check
│   ├── AndroidSafetynetAttestationVerifier.php — "android-safetynet" format (WebAuthn §8.5), JWS-wrapped SafetyNet
│   └── AppleAttestationVerifier.php       — "apple" format (WebAuthn §8.8), nonce-binding certificate extension only
└── Exception/
    ├── WebAuthnException.php              — abstract base (documented carve-out)
    ├── InvalidClientDataException.php
    ├── AttestationVerificationException.php
    ├── SignatureVerificationException.php
    ├── UnknownAttestationFormatException.php
    └── SignatureCounterException.php
```

---

## Key Classes and Responsibilities

- **`RegistrationCeremony`** / **`AssertionCeremony`** — the two public entry
  points. Each takes plain bytes/strings the app has already extracted from
  the browser's WebAuthn JSON response, validates them, and returns a
  `PublicKeyCredentialSource` for the app to persist.
- **`SecondFactorAssertionVerifier`** — thin adapter around `AssertionCeremony`
  that reports its outcome as `EzPhp\Contracts\SecondFactorResult` instead of
  a thrown exception / return value pair, so login-flow code can treat a
  passkey assertion the same way it treats `ez-php/two-factor`'s TOTP
  verification (see Design Decisions).
- **`ClientDataValidator`** — shared type/challenge/origin verification used
  by both ceremonies.
- **`AuthenticatorData`** — the single place that understands the
  authenticatorData binary layout (WebAuthn spec §6.1).
- **`Cbor\CborDecoder`** — hand-written, WebAuthn-scoped CBOR decoding; not a
  general-purpose CBOR library (see Design Decisions).
- **`Cose\CoseKey` + `Cose\Verifier\*`** — COSE public key parsing and
  per-algorithm signature verification (ES256, RS256, EdDSA).
- **`AttestationStatement\AttestationStatementVerifierRegistry`** —
  dispatches to one verifier per `fmt` (`none`, `packed`, `fido-u2f`,
  `tpm`, `android-key`, `android-safetynet`, `apple`).
- **`Tpm\TpmtPublicParser` + `Tpm\TpmsAttestParser`** — hand-written TPM 2.0
  structure readers scoped to exactly the `pubArea`/`certInfo` shapes a
  `tpm` attestation statement carries (RSA/ECC keys with TPM_ALG_NULL
  sub-fields; `TPM_ST_ATTEST_CERTIFY` only).
- **`Asn1\Asn1Reader`** — hand-written minimal DER reader used to pull one
  specific extension value out of an X.509 certificate (Android Key
  attestation, Apple nonce extension); not a general ASN.1 library.
- **`AttestationStatement\TpmAttestationVerifier`**,
  **`AndroidKeyAttestationVerifier`**, **`AndroidSafetynetAttestationVerifier`**,
  **`AppleAttestationVerifier`** — the four Phase 2 verifiers, each stateless
  and deriving all inputs from `$authenticatorData`/`AttestationStatement::$attStmt`
  passed to `verify()`, matching the Phase 1 verifier pattern.

---

## Design Decisions and Constraints

- **Framework-agnostic.** No dependency on `ez-php/http`, `ez-php/auth`, or
  `ez-php/framework`. The app supplies `ChallengeStoreInterface` and
  `CredentialRepositoryInterface`; this module has no persistence or HTTP
  layer of its own.
- **`ez-php/contracts` is a require-dev-only (soft) dependency, added solely
  for `SecondFactorAssertionVerifier`.** PSR-4 only resolves that class when
  something actually references it, so `src/SecondFactorAssertionVerifier.php`
  ships without pulling `ez-php/contracts` into a standalone install that
  never uses it — the module stays framework-agnostic per the bullet above
  (same reasoning as `ez-php/mail`'s `Job\SendMailableJob`). This is the one
  file in the module that references anything outside PHP/`ext-openssl`/
  `ext-sodium`.
- **`SecondFactorAssertionVerifier` does not merge this module with
  `ez-php/two-factor`.** They remain mutually exclusive as documented in
  both modules' "What Does NOT Belong Here" sections — this class only
  adapts `AssertionCeremony`'s result to the shared, logic-free
  `EzPhp\Contracts\SecondFactorResult` enum so application login-flow code
  can branch on one outcome type regardless of which second factor ran.
  `AssertionCeremony` itself is unchanged.
- **`SecondFactorAssertionVerifier` retains the verified credential on
  success, rather than discarding it.** `AssertionCeremony::verify()`
  returns an updated `PublicKeyCredentialSource` (new signature counter)
  that the caller must persist — collapsing that into a bare
  `SecondFactorResult` would silently drop the anti-clone signature-counter
  update. `getVerifiedCredential()` exposes it after a successful `verify()`
  call; it is reset to `null` on failure.
- **No network calls.** SafetyNet/Android-Key attestation chain-of-trust
  validation against a live root CA bundle is explicitly out of scope — this
  module verifies signatures are cryptographically valid for the presented
  certificate, not that the certificate is trusted by any external
  authority. An app needing strict live trust validation must add that
  itself.
- **Hand-written CBOR decoder.** PHP has no CBOR extension or stdlib
  support, and no existing ez-php module provides one — per root CLAUDE.md's
  "no heavy dependencies, check stdlib first," `Cbor\CborDecoder` is scoped
  to exactly the CBOR major types WebAuthn authenticators emit, not a
  general-purpose implementation.
- **Packed full-attestation is ES256/RS256 only.** EdDSA (COSE -8) full
  attestation via an x5c certificate is not supported in Phase 1 —
  `openssl_verify()` cannot verify Ed25519 signatures directly, and
  supporting it would require parsing the certificate's raw public key
  bytes out-of-band. Self-attestation (no x5c) already supports EdDSA via
  `EdDsaVerifier`. A `AttestationVerificationException` is thrown for an
  EdDSA full-attestation attempt rather than silently mis-verifying it.
- **Phase 2 trusted-vs-signature-verified semantics.** Every verifier
  (Phase 1 and Phase 2 alike) confirms the signature/structural binding is
  cryptographically valid for the *presented* certificate/key — none of
  them validate a certificate chain against a trusted root or metadata
  service (no network calls, consistent with the "No network calls" bullet
  above). `AttestationResult::$trusted` is `true` only where a
  certificate-backed signature was verified (`packed` full attestation,
  `fido-u2f`, `tpm`, `android-key`, `android-safetynet`); `apple` sets
  `trusted: false` since Apple's format carries no signature at all — only
  a nonce-binding certificate extension — so without chain validation
  there is no cryptographic proof beyond structural matching.
- **Algorithm scope (all formats).** ES256 (COSE -7, EC P-256/SHA-256) and
  RS256 (COSE -257, RSA/SHA-256) only. A TPM key using another algorithm,
  or a SafetyNet JWS header `alg` other than `RS256`, is rejected with
  `AttestationVerificationException` rather than silently mishandled.

---

## Testing Approach

- Test classes live in the shared `Tests\` namespace but must be uniquely
  named across the whole monorepo — the root `phpunit.xml` loads every
  package in one process, so a duplicate name is a fatal error, not a test
  failure. Prefix with `WebAuthn` when the obvious name is already taken.
- Signature-verifier tests (`Cose\Verifier\*`, attestation verifiers)
  generate real key material and signatures via PHP's `openssl`/`sodium`
  extensions at test-run time rather than using canned fixtures — appropriate
  for testing a verification primitive in isolation.
- `AuthenticatorData`/CBOR/ceremony-level tests build real (hand-encoded)
  binary payloads matching the actual wire format, never mocked byte
  strings that only coincidentally satisfy the parser.
- TPM/Android/Apple attestation tests follow the same rule: real
  certificates and structurally-correct hand-built binary payloads
  generated via real `openssl`/`sodium` crypto and hand-encoded wire-format
  bytes, never mocked byte strings. `AndroidKeyAttestationVerifierTest` and
  `AppleAttestationVerifierTest` additionally document an
  empirically-verified assumption about `openssl_x509_parse()`'s
  extension-value format (see those files' comments) since PHP's exact
  behavior for non-standard certificate extensions isn't officially
  documented.
- No MySQL/Redis/Docker services required — pure computation, no I/O.
- `SecondFactorAssertionVerifierTest` reuses `AssertionCeremonyTest`'s real-key-material fixture builders and asserts the same success/failure cases now report `SecondFactorResult::Satisfied`/`NotSatisfied` instead of a return value/exception pair.

---

## What Does NOT Belong Here

| Concern | Where it belongs |
|---|---|
| HTTP request/response handling, routing, controllers | The consuming application |
| Session or cookie-based challenge storage | The consuming application, via `ChallengeStoreInterface` |
| Credential persistence (database, ORM) | The consuming application, via `CredentialRepositoryInterface` |
| TOTP / one-time-password 2FA | `ez-php/two-factor` — bridged only via the shared `EzPhp\Contracts\SecondFactorResult` outcome type, not merged |
| Live attestation root-CA trust validation / metadata service lookups | Out of scope for this module entirely (no network calls) |