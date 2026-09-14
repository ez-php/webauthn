<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

use EzPhp\WebAuthn\AuthenticatorData;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;

/**
 * Verifies the "fido-u2f" attestation format (WebAuthn spec §8.6): U2F
 * authenticators sign a specifically reconstructed byte string, not
 * authenticatorData || clientDataHash directly. Always EC P-256/SHA-256, per
 * the U2F raw message format this predates WebAuthn from. Stateless — every
 * value it needs comes from parsing $authenticatorData.
 *
 * @package EzPhp\WebAuthn\AttestationStatement
 */
final class FidoU2fAttestationVerifier implements AttestationStatementVerifierInterface
{
    public function verify(AttestationStatement $statement, string $authenticatorData, string $clientDataHash): AttestationResult
    {
        $signature = $statement->attStmt['sig'] ?? null;
        $x5c = $statement->attStmt['x5c'] ?? null;

        if (!is_string($signature) || !is_array($x5c) || !isset($x5c[0]) || !is_string($x5c[0])) {
            throw new AttestationVerificationException('"fido-u2f" attestation statement is missing sig/x5c.');
        }

        $parsed = AuthenticatorData::parse($authenticatorData);
        $credentialPublicKey = $parsed->credentialPublicKey;

        if ($parsed->credentialId === null || $credentialPublicKey === null) {
            throw new AttestationVerificationException('"fido-u2f" attestation requires attested credential data in authenticatorData.');
        }

        $x = $credentialPublicKey->parameters[-2] ?? null;
        $y = $credentialPublicKey->parameters[-3] ?? null;

        if (!is_string($x) || !is_string($y)) {
            throw new AttestationVerificationException('"fido-u2f" attestation requires an EC2 credential public key.');
        }

        $publicKeyU2f = "\x04" . $x . $y;
        $signedData = "\x00" . $parsed->rpIdHash . $clientDataHash . $parsed->credentialId . $publicKeyU2f;

        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($x5c[0]), 64, "\n") . "-----END CERTIFICATE-----\n";
        $publicKey = openssl_pkey_get_public($pem);

        if ($publicKey === false) {
            throw new AttestationVerificationException('Could not read the x5c leaf certificate\'s public key.');
        }

        $result = openssl_verify($signedData, $signature, $publicKey, OPENSSL_ALGO_SHA256);

        if ($result !== 1) {
            throw new AttestationVerificationException('"fido-u2f" attestation signature verification failed.');
        }

        return new AttestationResult(trusted: true, attestationType: 'basic');
    }
}
