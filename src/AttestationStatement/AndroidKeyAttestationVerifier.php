<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

use EzPhp\WebAuthn\Asn1\Asn1Reader;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;

/**
 * Verifies the "android-key" attestation format (WebAuthn spec §8.4): same
 * signature scheme as "packed" full attestation, plus a check that the
 * leaf certificate's Android key attestation extension
 * (OID 1.3.6.1.4.1.11129.2.1.17) carries an attestationChallenge matching
 * clientDataHash. See this plan's Task 4 for the documented scope limit
 * (no certificate-profile or chain-of-trust validation).
 *
 * @package EzPhp\WebAuthn\AttestationStatement
 */
final class AndroidKeyAttestationVerifier implements AttestationStatementVerifierInterface
{
    private const string KEY_DESCRIPTION_OID = '1.3.6.1.4.1.11129.2.1.17';
    private const int ATTESTATION_CHALLENGE_INDEX = 4;

    /**
     * {@inheritDoc}
     */
    public function verify(AttestationStatement $statement, string $authenticatorData, string $clientDataHash): AttestationResult
    {
        $algorithm = $statement->attStmt['alg'] ?? null;
        $signature = $statement->attStmt['sig'] ?? null;
        $x5c = $statement->attStmt['x5c'] ?? null;

        if (!is_int($algorithm) || !is_string($signature) || !is_array($x5c) || !isset($x5c[0]) || !is_string($x5c[0])) {
            throw new AttestationVerificationException('"android-key" attestation statement is missing alg/sig/x5c.');
        }

        $leafCertificateDer = $x5c[0];
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($leafCertificateDer), 64, "\n") . "-----END CERTIFICATE-----\n";
        $publicKey = openssl_pkey_get_public($pem);

        if ($publicKey === false) {
            throw new AttestationVerificationException('Could not read the x5c leaf certificate\'s public key.');
        }

        $digestAlgorithm = match ($algorithm) {
            -7, -257 => OPENSSL_ALGO_SHA256,
            default => throw new AttestationVerificationException("Unsupported COSE algorithm for android-key attestation: {$algorithm}"),
        };

        $signedData = $authenticatorData . $clientDataHash;
        $result = openssl_verify($signedData, $signature, $publicKey, $digestAlgorithm);

        if ($result !== 1) {
            throw new AttestationVerificationException('"android-key" attestation signature verification failed.');
        }

        $attestationChallenge = $this->extractAttestationChallenge($pem);

        if (!hash_equals($clientDataHash, $attestationChallenge)) {
            throw new AttestationVerificationException('Android key attestation challenge does not match clientDataHash.');
        }

        return new AttestationResult(trusted: true, attestationType: 'basic');
    }

    private function extractAttestationChallenge(string $certificatePem): string
    {
        $parsed = openssl_x509_parse($certificatePem, true);

        if ($parsed === false) {
            throw new AttestationVerificationException('Could not parse the x5c leaf certificate.');
        }

        /** @var array{extensions?: array<string, string>} $parsed */
        $keyDescription = $parsed['extensions'][self::KEY_DESCRIPTION_OID] ?? null;

        if (!is_string($keyDescription)) {
            throw new AttestationVerificationException('Leaf certificate is missing the Android key attestation extension.');
        }

        $elements = Asn1Reader::readSequenceElements($keyDescription);

        if (!isset($elements[self::ATTESTATION_CHALLENGE_INDEX])) {
            throw new AttestationVerificationException('Android key attestation extension is missing attestationChallenge.');
        }

        return $elements[self::ATTESTATION_CHALLENGE_INDEX]['value'];
    }
}
