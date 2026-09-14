<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn;

use EzPhp\WebAuthn\Cose\SignatureVerifierInterface;
use EzPhp\WebAuthn\Exception\InvalidClientDataException;
use EzPhp\WebAuthn\Exception\SignatureCounterException;
use EzPhp\WebAuthn\Exception\SignatureVerificationException;

/**
 * Orchestrates server-side verification of a WebAuthn assertion
 * (authentication) ceremony: clientDataJSON validation, credential lookup,
 * signature verification, and signature-counter clone detection.
 *
 * @package EzPhp\WebAuthn
 */
final class AssertionCeremony
{
    /**
     * @param array<int, SignatureVerifierInterface> $verifiersByAlgorithm
     */
    public function __construct(
        private readonly RelyingParty $relyingParty,
        private readonly array $verifiersByAlgorithm,
    ) {
    }

    /**
     * @param ?string $expectedUserHandle When the application already knows which
     *     user is authenticating (e.g. a username-first flow), it MUST pass the
     *     expected user handle here. Without it, any credential that verifies
     *     successfully is accepted regardless of which user it belongs to —
     *     which is only safe for a discoverable-credential ("usernameless")
     *     flow where the credential itself identifies the user.
     *
     * @throws InvalidClientDataException
     * @throws SignatureVerificationException
     * @throws SignatureCounterException
     */
    public function verify(
        Challenge $challenge,
        string $clientDataJson,
        string $authenticatorData,
        string $signature,
        string $credentialId,
        CredentialRepositoryInterface $credentials,
        ?string $expectedUserHandle = null,
    ): PublicKeyCredentialSource {
        ClientDataValidator::validate($clientDataJson, 'webauthn.get', $challenge, $this->relyingParty, new \DateTimeImmutable());

        $storedSource = $credentials->findByCredentialId($credentialId);

        if ($storedSource === null) {
            throw new InvalidClientDataException("No credential registered for ID \"{$credentialId}\".");
        }

        if ($expectedUserHandle !== null && !hash_equals($expectedUserHandle, $storedSource->userHandle)) {
            throw new InvalidClientDataException('Credential does not belong to the expected user.');
        }

        $parsedAuthenticatorData = AuthenticatorData::parse($authenticatorData);

        $expectedRpIdHash = hash('sha256', $this->relyingParty->id, true);

        if (!hash_equals($expectedRpIdHash, $parsedAuthenticatorData->rpIdHash)) {
            throw new InvalidClientDataException('authenticatorData RP ID hash does not match the configured relying party.');
        }

        if (!$parsedAuthenticatorData->userPresent) {
            throw new InvalidClientDataException('authenticatorData does not report user presence.');
        }

        if ($storedSource->signCount !== 0 && $parsedAuthenticatorData->signCount <= $storedSource->signCount) {
            throw new SignatureCounterException('Signature counter did not strictly increase — possible cloned authenticator.');
        }

        $verifier = $this->verifiersByAlgorithm[$storedSource->publicKey->algorithm] ?? null;

        if ($verifier === null) {
            throw new SignatureVerificationException("No signature verifier registered for COSE algorithm {$storedSource->publicKey->algorithm}.");
        }

        $clientDataHash = hash('sha256', $clientDataJson, true);
        $signedData = $authenticatorData . $clientDataHash;

        if (!$verifier->verify($storedSource->publicKey, $signedData, $signature)) {
            throw new SignatureVerificationException('Assertion signature verification failed.');
        }

        return $storedSource->withSignCount($parsedAuthenticatorData->signCount);
    }
}
