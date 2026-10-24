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

The module verifies ceremonies server-side; it never stores state and never
talks to the browser. The application supplies three things:

| What | Contract |
|---|---|
| Relying party (RP ID, name, allowed origins) | `RelyingParty` value object |
| Single-use challenge storage | `ChallengeStoreInterface` — `generate(): Challenge`, `consume(string $id): ?Challenge` |
| Credential persistence | `CredentialRepositoryInterface` — `findByCredentialId()`, `findByUserHandle()`, `save()` |

A `Challenge` carries an `id`, the raw random `value` (at least 16 bytes) and
an `expiresAt` timestamp; `consume()` must return it at most once.

```php
use EzPhp\WebAuthn\Challenge;
use EzPhp\WebAuthn\ChallengeStoreInterface;

final class SessionChallengeStore implements ChallengeStoreInterface
{
    public function generate(): Challenge
    {
        $challenge = new Challenge(
            id: bin2hex(random_bytes(16)),
            value: random_bytes(32),
            expiresAt: new \DateTimeImmutable('+5 minutes'),
        );
        $_SESSION['webauthn_challenges'][$challenge->id] = $challenge;

        return $challenge;
    }

    public function consume(string $challengeId): ?Challenge
    {
        $challenge = $_SESSION['webauthn_challenges'][$challengeId] ?? null;
        unset($_SESSION['webauthn_challenges'][$challengeId]);

        return $challenge instanceof Challenge ? $challenge : null;
    }
}
```

`CredentialRepositoryInterface::save()` receives a `PublicKeyCredentialSource`
(`credentialId`, `publicKey` (`CoseKey`), `signCount`, `aaguid`, `userHandle`,
`transports`, `attestationResult`) and must insert or update it by credential
ID — e.g. a table keyed by `credentialId` holding `serialize($source)` plus the
`userHandle` for `findByUserHandle()`.

### Relying party and verifiers

```php
use EzPhp\WebAuthn\AttestationStatement\AndroidKeyAttestationVerifier;
use EzPhp\WebAuthn\AttestationStatement\AndroidSafetynetAttestationVerifier;
use EzPhp\WebAuthn\AttestationStatement\AppleAttestationVerifier;
use EzPhp\WebAuthn\AttestationStatement\AttestationStatementVerifierRegistry;
use EzPhp\WebAuthn\AttestationStatement\FidoU2fAttestationVerifier;
use EzPhp\WebAuthn\AttestationStatement\NoneAttestationVerifier;
use EzPhp\WebAuthn\AttestationStatement\PackedAttestationVerifier;
use EzPhp\WebAuthn\AttestationStatement\TpmAttestationVerifier;
use EzPhp\WebAuthn\Cose\Verifier\EdDsaVerifier;
use EzPhp\WebAuthn\Cose\Verifier\Es256Verifier;
use EzPhp\WebAuthn\Cose\Verifier\Rs256Verifier;
use EzPhp\WebAuthn\RelyingParty;

$relyingParty = new RelyingParty(
    id: 'example.com',
    name: 'Example',
    allowedOrigins: ['https://example.com'],
);

// COSE algorithm identifier => signature verifier
$signatureVerifiers = [
    -7   => new Es256Verifier(),
    -257 => new Rs256Verifier(),
    -8   => new EdDsaVerifier(),
];

// Attestation format (`fmt`) => verifier. Register only the formats you accept;
// `none` alone is enough when the RP requests `attestation: "none"`.
$attestationVerifiers = new AttestationStatementVerifierRegistry([
    'none'              => new NoneAttestationVerifier(),
    'packed'            => new PackedAttestationVerifier($signatureVerifiers),
    'tpm'               => new TpmAttestationVerifier(),
    'android-key'       => new AndroidKeyAttestationVerifier(),
    'android-safetynet' => new AndroidSafetynetAttestationVerifier(),
    'apple'             => new AppleAttestationVerifier(),
    'fido-u2f'          => new FidoU2fAttestationVerifier(),
]);
```

An attestation format without a registered verifier throws
`UnknownAttestationFormatException`. `AttestationResult::$trusted` reports
whether a verifier validated a certificate chain; live root-of-trust checks
against the FIDO Metadata Service live in `ez-php/webauthn-metadata`.

### Registration

1. Issue a challenge and send the creation options to the browser:

```php
$challenge = $challengeStore->generate();

$options = [
    'challenge' => rtrim(strtr(base64_encode($challenge->value), '+/', '-_'), '='),
    'rp'        => ['id' => $relyingParty->id, 'name' => $relyingParty->name],
    'user'      => ['id' => base64url($userHandle), 'name' => $email, 'displayName' => $name],
    'pubKeyCredParams' => [['type' => 'public-key', 'alg' => -7], ['type' => 'public-key', 'alg' => -257], ['type' => 'public-key', 'alg' => -8]],
    'attestation' => 'none',
];
// keep $challenge->id with the request (hidden field, session) to consume it later
```

2. The browser calls `navigator.credentials.create({ publicKey: options })` and
   posts back `response.clientDataJSON`, `response.attestationObject` and
   `response.getTransports()`.

3. Verify and persist:

```php
use EzPhp\WebAuthn\RegistrationCeremony;

$challenge = $challengeStore->consume($challengeId)
    ?? throw new \RuntimeException('Unknown or already used challenge.');

$ceremony = new RegistrationCeremony($relyingParty, $attestationVerifiers);

$credentialSource = $ceremony->verify(
    $challenge,
    $clientDataJson,      // raw bytes (base64url-decoded)
    $attestationObject,   // raw CBOR bytes (base64url-decoded)
    $userHandle,          // the user.id you sent in the options
    $transports,          // e.g. ['internal', 'hybrid']
);

$credentialRepository->save($credentialSource);
```

### Authentication (assertion)

1. Issue a challenge, optionally listing the user's credentials:

```php
$challenge = $challengeStore->generate();

$options = [
    'challenge'        => rtrim(strtr(base64_encode($challenge->value), '+/', '-_'), '='),
    'rpId'             => $relyingParty->id,
    'allowCredentials' => array_map(
        fn ($source) => ['type' => 'public-key', 'id' => base64url($source->credentialId), 'transports' => $source->transports],
        $credentialRepository->findByUserHandle($userHandle),
    ), // omit for a usernameless (discoverable-credential) login
];
```

2. The browser calls `navigator.credentials.get({ publicKey: options })` and
   posts back `rawId`, `response.clientDataJSON`, `response.authenticatorData`
   and `response.signature`.

3. Verify and store the new signature counter:

```php
use EzPhp\WebAuthn\AssertionCeremony;

$challenge = $challengeStore->consume($challengeId)
    ?? throw new \RuntimeException('Unknown or already used challenge.');

$ceremony = new AssertionCeremony($relyingParty, $signatureVerifiers);

$credentialSource = $ceremony->verify(
    $challenge,
    $clientDataJson,
    $authenticatorData,
    $signature,
    $credentialId,          // rawId
    $credentialRepository,
    $userHandle,            // pass it in a username-first flow; null only for usernameless login
);

$credentialRepository->save($credentialSource); // persists the increased signCount
// $credentialSource->userHandle identifies the authenticated user
```

Every verification failure throws a subclass of
`EzPhp\WebAuthn\Exception\WebAuthnException` (`InvalidClientDataException`,
`AttestationVerificationException`, `SignatureVerificationException`,
`SignatureCounterException`, `UnknownAttestationFormatException`). In both
ceremonies all binary inputs are the raw bytes — base64url-decode what the
browser sent before passing it in. (`base64url()` above stands for your own
`rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=')` helper.)

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
