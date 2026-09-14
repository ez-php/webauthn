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

## License

MIT
