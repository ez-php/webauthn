# ez-php/webauthn

WebAuthn / FIDO2 passkey authentication: registration and assertion
ceremonies, attestation verification, challenge handling.

---

## Installation

```bash
composer require ez-php/webauthn
```

---

## Usage

See `docs/superpowers/specs/2026-09-14-webauthn-module-design.md` for the
full design. Quick start:

```php
$relyingParty = new RelyingParty(id: 'example.com', name: 'Example', allowedOrigins: ['https://example.com']);
$ceremony = new RegistrationCeremony($relyingParty);
$credentialSource = $ceremony->verify($challenge, $clientResponse);
$credentialRepository->save($credentialSource);
```

---

## Second-factor login flows

If your application also uses `ez-php/two-factor` and wants one result type
for either mechanism, wrap assertion verification with
`SecondFactorAssertionVerifier` — it reports the same
`EzPhp\Contracts\SecondFactorResult` enum `TwoFactorManager::verifyForUser()`
returns. This requires adding `ez-php/contracts` yourself (it's a
require-dev-only dependency of this package, not a runtime one):

```php
use EzPhp\WebAuthn\SecondFactorAssertionVerifier;

$verifier = new SecondFactorAssertionVerifier($ceremony);
$result = $verifier->verify($challenge, $clientDataJson, $authenticatorData, $signature, $credentialId, $credentialRepository);

if ($result === \EzPhp\Contracts\SecondFactorResult::Satisfied) {
    $credentialRepository->save($verifier->getVerifiedCredential()); // persist the updated sign count
}
```

This does not merge `ez-php/webauthn` with `ez-php/two-factor` — both modules
remain independent and mutually exclusive; only the outcome type is shared.

---

## License

MIT
