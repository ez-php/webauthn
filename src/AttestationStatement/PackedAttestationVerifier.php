<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

use EzPhp\WebAuthn\AuthenticatorData;
use EzPhp\WebAuthn\Cose\CoseKey;
use EzPhp\WebAuthn\Cose\SignatureVerifierInterface;
use EzPhp\WebAuthn\Cose\Verifier\EdDsaVerifier;
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

    /**
     * {@inheritDoc}
     */
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

    /**
     * Ed25519 SubjectPublicKeyInfo header (RFC 8410): SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (33 bytes) }.
     * The 32-byte raw key follows; the whole DER structure is always 44 bytes.
     */
    private const string ED25519_SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

    private function verifyFullAttestation(int $algorithm, string $signature, string $signedData, string $leafCertificateDer): AttestationResult
    {
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($leafCertificateDer), 64, "\n") . "-----END CERTIFICATE-----\n";
        $publicKey = openssl_pkey_get_public($pem);

        if ($publicKey === false) {
            throw new AttestationVerificationException('Could not read the x5c leaf certificate\'s public key.');
        }

        $ed25519Key = self::ed25519RawKey($publicKey);

        if ($algorithm === -8 || $ed25519Key !== null) {
            return $this->verifyEdDsaFullAttestation($algorithm, $signature, $signedData, $ed25519Key);
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

    /**
     * EdDSA full attestation: openssl_verify() is not used for Ed25519 (not available
     * on every PHP/OpenSSL build), so the raw key is taken from the certificate's
     * SPKI and checked with libsodium through EdDsaVerifier, as self-attestation does.
     * The statement's alg and the certificate's key type must agree in both directions.
     */
    private function verifyEdDsaFullAttestation(int $algorithm, string $signature, string $signedData, ?string $rawKey): AttestationResult
    {
        if ($algorithm !== -8 || $rawKey === null) {
            throw new AttestationVerificationException(
                "Full attestation algorithm {$algorithm} does not match the x5c leaf certificate's key type.",
            );
        }

        $coseKey = new CoseKey(algorithm: -8, parameters: [1 => 1, 3 => -8, -1 => 6, -2 => $rawKey]);

        if (!(new EdDsaVerifier())->verify($coseKey, $signedData, $signature)) {
            throw new AttestationVerificationException('Full attestation signature verification failed.');
        }

        return new AttestationResult(trusted: true, attestationType: 'basic');
    }

    /**
     * The certificate's raw 32-byte Ed25519 public key, or null for any other key type.
     */
    private static function ed25519RawKey(\OpenSSLAsymmetricKey $publicKey): ?string
    {
        $details = openssl_pkey_get_details($publicKey);
        $pem = is_array($details) && is_string($details['key'] ?? null) ? $details['key'] : '';
        $spki = base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);

        if (!is_string($spki) || strlen($spki) !== 44 || !str_starts_with($spki, self::ED25519_SPKI_PREFIX)) {
            return null;
        }

        return substr($spki, 12);
    }
}
