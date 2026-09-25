<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

use EzPhp\WebAuthn\Exception\AttestationVerificationException;

/**
 * Verifies the "android-safetynet" attestation format (WebAuthn spec §8.5):
 * a JWS-wrapped Google SafetyNet attestation. See this plan's Task 5 for
 * the documented scope decision on ctsProfileMatch (parsed, not enforced)
 * and the algorithm scope (RS256 only).
 *
 * @package EzPhp\WebAuthn\AttestationStatement
 */
final class AndroidSafetynetAttestationVerifier implements AttestationStatementVerifierInterface
{
    private const string EXPECTED_LEAF_CN = 'attest.android.com';

    /**
     * {@inheritDoc}
     */
    public function verify(AttestationStatement $statement, string $authenticatorData, string $clientDataHash): AttestationResult
    {
        $response = $statement->attStmt['response'] ?? null;

        if (!is_string($response)) {
            throw new AttestationVerificationException('"android-safetynet" attestation statement is missing response.');
        }

        $parts = explode('.', $response);

        if (count($parts) !== 3) {
            throw new AttestationVerificationException('"android-safetynet" response is not a valid JWS compact serialization.');
        }

        [$headerB64, $payloadB64, $signatureB64] = $parts;

        $header = $this->decodeJsonSegment($headerB64);
        $payload = $this->decodeJsonSegment($payloadB64);

        if (($header['alg'] ?? null) !== 'RS256') {
            throw new AttestationVerificationException('Unsupported or missing SafetyNet JWS algorithm.');
        }

        $x5c = $header['x5c'] ?? null;

        if (!is_array($x5c) || !isset($x5c[0]) || !is_string($x5c[0])) {
            throw new AttestationVerificationException('SafetyNet JWS header is missing x5c.');
        }

        $leafCertificateDer = base64_decode($x5c[0], strict: true);

        if ($leafCertificateDer === false) {
            throw new AttestationVerificationException('SafetyNet JWS header x5c is not valid base64.');
        }

        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($leafCertificateDer), 64, "\n") . "-----END CERTIFICATE-----\n";
        $publicKey = openssl_pkey_get_public($pem);

        if ($publicKey === false) {
            throw new AttestationVerificationException('Could not read the SafetyNet leaf certificate\'s public key.');
        }

        $parsedCertificate = openssl_x509_parse($pem);

        if ($parsedCertificate === false) {
            throw new AttestationVerificationException('Could not parse the SafetyNet leaf certificate.');
        }

        /** @var array{subject?: array{CN?: string}} $parsedCertificate */
        $commonName = $parsedCertificate['subject']['CN'] ?? null;

        if ($commonName !== self::EXPECTED_LEAF_CN) {
            throw new AttestationVerificationException('SafetyNet leaf certificate CN does not match ' . self::EXPECTED_LEAF_CN . '.');
        }

        $signature = $this->base64UrlDecode($signatureB64);
        $result = openssl_verify($headerB64 . '.' . $payloadB64, $signature, $publicKey, OPENSSL_ALGO_SHA256);

        if ($result !== 1) {
            throw new AttestationVerificationException('SafetyNet JWS signature verification failed.');
        }

        $expectedNonce = base64_encode(hash('sha256', $authenticatorData . $clientDataHash, true));
        $nonce = $payload['nonce'] ?? null;

        if (!is_string($nonce) || !hash_equals($expectedNonce, $nonce)) {
            throw new AttestationVerificationException('SafetyNet nonce does not match the expected attestation hash.');
        }

        return new AttestationResult(trusted: true, attestationType: 'basic');
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJsonSegment(string $base64UrlSegment): array
    {
        $json = $this->base64UrlDecode($base64UrlSegment);

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new AttestationVerificationException('SafetyNet JWS segment is not valid JSON.', previous: $exception);
        }

        if (!is_array($decoded)) {
            throw new AttestationVerificationException('SafetyNet JWS segment must decode to an object.');
        }

        $result = [];

        foreach ($decoded as $key => $value) {
            if (!is_string($key)) {
                throw new AttestationVerificationException('SafetyNet JWS segment must decode to an object.');
            }

            $result[$key] = $value;
        }

        return $result;
    }

    private function base64UrlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/'), strict: true);

        if ($decoded === false) {
            throw new AttestationVerificationException('SafetyNet JWS segment is not valid base64url.');
        }

        return $decoded;
    }
}
