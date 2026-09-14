<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

use EzPhp\WebAuthn\AuthenticatorData;
use EzPhp\WebAuthn\Cose\SignatureVerifierInterface;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;

/**
 * Verifies the "packed" attestation format (WebAuthn spec §8.2): self
 * attestation (signed by the credential's own key) or basic/full attestation
 * (signed by an attestation certificate presented in x5c).
 *
 * Chain-of-trust validation of the x5c leaf certificate to a trusted root or
 * metadata service is out of scope for this module (no network calls) — see
 * the module's CLAUDE.md Design Decisions. This verifier confirms the
 * signature is cryptographically valid for the presented certificate/key,
 * not that the certificate is trusted by any authority.
 *
 * @package EzPhp\WebAuthn\AttestationStatement
 */
final class PackedAttestationVerifier implements AttestationStatementVerifierInterface
{
    /**
     * @param array<int, SignatureVerifierInterface> $verifiersByAlgorithm
     */
    public function __construct(
        private readonly array $verifiersByAlgorithm,
    ) {
    }

    public function verify(AttestationStatement $statement, string $authenticatorData, string $clientDataHash): AttestationResult
    {
        $algorithm = $statement->attStmt['alg'] ?? null;
        $signature = $statement->attStmt['sig'] ?? null;

        if (!is_int($algorithm) || !is_string($signature)) {
            throw new AttestationVerificationException('"packed" attestation statement is missing alg/sig.');
        }

        $signedData = $authenticatorData . $clientDataHash;
        $x5c = $statement->attStmt['x5c'] ?? null;

        if ($x5c === null) {
            return $this->verifySelfAttestation($algorithm, $signature, $signedData, $authenticatorData);
        }

        if (!is_array($x5c) || !isset($x5c[0]) || !is_string($x5c[0])) {
            throw new AttestationVerificationException('"packed" attestation statement has an invalid x5c.');
        }

        return $this->verifyFullAttestation($algorithm, $signature, $signedData, $x5c[0]);
    }

    private function verifySelfAttestation(int $algorithm, string $signature, string $signedData, string $authenticatorData): AttestationResult
    {
        try {
            $credentialPublicKey = AuthenticatorData::parse($authenticatorData)->credentialPublicKey;
        } catch (\InvalidArgumentException $e) {
            throw new AttestationVerificationException('"packed" attestation could not parse authenticatorData: ' . $e->getMessage(), previous: $e);
        }

        if ($credentialPublicKey === null) {
            throw new AttestationVerificationException('Self-attestation requires attested credential data in authenticatorData.');
        }

        if ($algorithm !== $credentialPublicKey->algorithm) {
            throw new AttestationVerificationException('Self-attestation algorithm does not match the credential\'s own algorithm.');
        }

        $verifier = $this->verifiersByAlgorithm[$algorithm] ?? null;

        if ($verifier === null) {
            throw new AttestationVerificationException("No signature verifier registered for COSE algorithm {$algorithm}.");
        }

        if (!$verifier->verify($credentialPublicKey, $signedData, $signature)) {
            throw new AttestationVerificationException('Self-attestation signature verification failed.');
        }

        return new AttestationResult(trusted: false, attestationType: 'self');
    }

    private function verifyFullAttestation(int $algorithm, string $signature, string $signedData, string $leafCertificateDer): AttestationResult
    {
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($leafCertificateDer), 64, "\n") . "-----END CERTIFICATE-----\n";
        $publicKey = openssl_pkey_get_public($pem);

        if ($publicKey === false) {
            throw new AttestationVerificationException('Could not read the x5c leaf certificate\'s public key.');
        }

        $digestAlgorithm = match ($algorithm) {
            -7 => OPENSSL_ALGO_SHA256,
            -257 => OPENSSL_ALGO_SHA256,
            default => throw new AttestationVerificationException("Unsupported COSE algorithm for full attestation: {$algorithm}"),
        };

        $result = openssl_verify($signedData, $signature, $publicKey, $digestAlgorithm);

        if ($result !== 1) {
            throw new AttestationVerificationException('Full attestation signature verification failed.');
        }

        return new AttestationResult(trusted: true, attestationType: 'basic');
    }
}
