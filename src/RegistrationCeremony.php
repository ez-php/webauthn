<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn;

use EzPhp\WebAuthn\AttestationStatement\AttestationStatement;
use EzPhp\WebAuthn\AttestationStatement\AttestationStatementVerifierRegistry;
use EzPhp\WebAuthn\Cbor\CborDecoder;
use EzPhp\WebAuthn\Exception\InvalidClientDataException;

/**
 * Orchestrates server-side verification of a WebAuthn registration
 * ceremony: clientDataJSON validation, authenticatorData parsing, and
 * attestation statement verification.
 *
 * @package EzPhp\WebAuthn
 */
final class RegistrationCeremony
{
    public function __construct(
        private readonly RelyingParty $relyingParty,
        private readonly AttestationStatementVerifierRegistry $attestationVerifiers,
    ) {
    }

    /**
     * @param list<string> $transports
     *
     * @throws InvalidClientDataException
     * @throws \EzPhp\WebAuthn\Exception\AttestationVerificationException
     * @throws \EzPhp\WebAuthn\Exception\UnknownAttestationFormatException
     */
    public function verify(
        Challenge $challenge,
        string $clientDataJson,
        string $attestationObject,
        string $userHandle,
        array $transports = [],
    ): PublicKeyCredentialSource {
        ClientDataValidator::validate($clientDataJson, 'webauthn.create', $challenge, $this->relyingParty, new \DateTimeImmutable());

        /** @var mixed $decoded */
        $decoded = CborDecoder::decode($attestationObject);

        if (!is_array($decoded) || !isset($decoded['fmt'], $decoded['attStmt'], $decoded['authData'])
            || !is_string($decoded['fmt']) || !is_array($decoded['attStmt']) || !is_string($decoded['authData'])
        ) {
            throw new InvalidClientDataException('attestationObject is missing fmt/attStmt/authData.');
        }

        $authenticatorData = AuthenticatorData::parse($decoded['authData']);

        $expectedRpIdHash = hash('sha256', $this->relyingParty->id, true);

        if (!hash_equals($expectedRpIdHash, $authenticatorData->rpIdHash)) {
            throw new InvalidClientDataException('authenticatorData RP ID hash does not match the configured relying party.');
        }

        if (!$authenticatorData->userPresent) {
            throw new InvalidClientDataException('authenticatorData does not report user presence.');
        }

        if ($authenticatorData->credentialId === null || $authenticatorData->credentialPublicKey === null) {
            throw new InvalidClientDataException('authenticatorData is missing attested credential data.');
        }

        $attStmt = $decoded['attStmt'];

        foreach (array_keys($attStmt) as $key) {
            if (!is_string($key)) {
                throw new InvalidClientDataException('attStmt keys must be strings.');
            }
        }

        /** @var array<string, mixed> $attStmt */
        $clientDataHash = hash('sha256', $clientDataJson, true);
        $statement = new AttestationStatement(fmt: $decoded['fmt'], attStmt: $attStmt);

        $attestationResult = $this->attestationVerifiers->verify($statement, $decoded['authData'], $clientDataHash);

        return new PublicKeyCredentialSource(
            credentialId: $authenticatorData->credentialId,
            publicKey: $authenticatorData->credentialPublicKey,
            signCount: $authenticatorData->signCount,
            aaguid: $authenticatorData->aaguid,
            userHandle: $userHandle,
            transports: $transports,
            attestationResult: $attestationResult,
        );
    }
}
