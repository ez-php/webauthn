<?php

declare(strict_types=1);

namespace Tests\AttestationStatement;

use EzPhp\WebAuthn\AttestationStatement\AndroidSafetynetAttestationVerifier;
use EzPhp\WebAuthn\AttestationStatement\AttestationStatement;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;
use Tests\TestCase;

/**
 * Class AndroidSafetynetAttestationVerifierTest
 *
 * @package Tests\AttestationStatement
 */
final class AndroidSafetynetAttestationVerifierTest extends TestCase
{
    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    /**
     * @return array{0: string, 1: \OpenSSLAsymmetricKey}
     */
    private function buildLeafCertificate(string $commonName = 'attest.android.com'): array
    {
        $keyPair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($keyPair);
        $csr = openssl_csr_new(['commonName' => $commonName], $keyPair, ['digest_alg' => 'sha256']);
        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);
        $cert = openssl_csr_sign($csr, null, $keyPair, 1, ['digest_alg' => 'sha256']);
        self::assertNotFalse($cert);
        openssl_x509_export($cert, $certPem);
        self::assertIsString($certPem);
        $der = base64_decode(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n"], '', $certPem), strict: true);
        self::assertIsString($der);

        return [$der, $keyPair];
    }

    public function test_verifies_a_valid_safetynet_attestation(): void
    {
        [$certDer, $keyPair] = $this->buildLeafCertificate();

        $authenticatorData = 'authenticator-data-bytes';
        $clientDataHash = hash('sha256', 'client-data', true);
        $nonce = base64_encode(hash('sha256', $authenticatorData . $clientDataHash, true));

        $header = ['alg' => 'RS256', 'x5c' => [base64_encode($certDer)]];
        $payload = ['nonce' => $nonce, 'timestampMs' => 1000, 'apkPackageName' => 'com.example', 'ctsProfileMatch' => true];

        $headerB64 = $this->base64Url((string) json_encode($header));
        $payloadB64 = $this->base64Url((string) json_encode($payload));

        openssl_sign($headerB64 . '.' . $payloadB64, $signature, $keyPair, OPENSSL_ALGO_SHA256);
        $response = $headerB64 . '.' . $payloadB64 . '.' . $this->base64Url($signature);

        $verifier = new AndroidSafetynetAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'android-safetynet', attStmt: ['ver' => '1', 'response' => $response]);

        $result = $verifier->verify($statement, $authenticatorData, $clientDataHash);

        self::assertTrue($result->trusted);
        self::assertSame('basic', $result->attestationType);
    }

    public function test_rejects_a_nonce_mismatch(): void
    {
        [$certDer, $keyPair] = $this->buildLeafCertificate();

        $header = ['alg' => 'RS256', 'x5c' => [base64_encode($certDer)]];
        $payload = ['nonce' => base64_encode('wrong-nonce-value-000000000000'), 'ctsProfileMatch' => true];

        $headerB64 = $this->base64Url((string) json_encode($header));
        $payloadB64 = $this->base64Url((string) json_encode($payload));

        openssl_sign($headerB64 . '.' . $payloadB64, $signature, $keyPair, OPENSSL_ALGO_SHA256);
        $response = $headerB64 . '.' . $payloadB64 . '.' . $this->base64Url($signature);

        $verifier = new AndroidSafetynetAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'android-safetynet', attStmt: ['ver' => '1', 'response' => $response]);

        $this->expectException(AttestationVerificationException::class);

        $verifier->verify($statement, 'authenticator-data-bytes', hash('sha256', 'client-data', true));
    }

    public function test_rejects_a_malformed_response(): void
    {
        $verifier = new AndroidSafetynetAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'android-safetynet', attStmt: ['ver' => '1', 'response' => 'not-a-jws']);

        $this->expectException(AttestationVerificationException::class);

        $verifier->verify($statement, 'authenticator-data-bytes', hash('sha256', 'client-data', true));
    }

    /**
     * A JWS compact serialization: base64url(header).base64url(payload).base64url(signature).
     *
     * @param array<string, mixed>|string $header  Array → JSON-encoded; string → used as the raw segment
     * @param array<string, mixed>|string $payload Array → JSON-encoded; string → used as the raw segment
     */
    private function jws(array|string $header, array|string $payload, \OpenSSLAsymmetricKey $signingKey): string
    {
        $headerB64 = is_array($header) ? $this->base64Url((string) json_encode($header)) : $header;
        $payloadB64 = is_array($payload) ? $this->base64Url((string) json_encode($payload)) : $payload;
        openssl_sign($headerB64 . '.' . $payloadB64, $signature, $signingKey, OPENSSL_ALGO_SHA256);

        return $headerB64 . '.' . $payloadB64 . '.' . $this->base64Url($signature);
    }

    /**
     * @param array<string, mixed> $attStmt
     */
    private function verifyStatement(array $attStmt): void
    {
        (new AndroidSafetynetAttestationVerifier())->verify(
            new AttestationStatement(fmt: 'android-safetynet', attStmt: $attStmt),
            'authenticator-data-bytes',
            hash('sha256', 'client-data', true),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function validPayload(): array
    {
        return ['nonce' => base64_encode(hash('sha256', 'authenticator-data-bytes' . hash('sha256', 'client-data', true), true))];
    }

    public function test_rejects_a_statement_without_response(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('missing response');

        $this->verifyStatement(['ver' => '1']);
    }

    public function test_rejects_a_non_rs256_algorithm(): void
    {
        [$certDer, $keyPair] = $this->buildLeafCertificate();

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('Unsupported or missing SafetyNet JWS algorithm');

        $this->verifyStatement(['response' => $this->jws(['alg' => 'HS256', 'x5c' => [base64_encode($certDer)]], $this->validPayload(), $keyPair)]);
    }

    public function test_rejects_a_header_without_x5c(): void
    {
        [, $keyPair] = $this->buildLeafCertificate();

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('missing x5c');

        $this->verifyStatement(['response' => $this->jws(['alg' => 'RS256'], $this->validPayload(), $keyPair)]);
    }

    public function test_rejects_an_x5c_entry_that_is_not_base64(): void
    {
        [, $keyPair] = $this->buildLeafCertificate();

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('x5c is not valid base64');

        $this->verifyStatement(['response' => $this->jws(['alg' => 'RS256', 'x5c' => ['not base64!!']], $this->validPayload(), $keyPair)]);
    }

    public function test_rejects_an_unreadable_leaf_certificate(): void
    {
        [, $keyPair] = $this->buildLeafCertificate();

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage("leaf certificate's public key");

        $this->verifyStatement(['response' => $this->jws(['alg' => 'RS256', 'x5c' => [base64_encode('not a certificate')]], $this->validPayload(), $keyPair)]);
    }

    public function test_rejects_a_leaf_certificate_for_another_host(): void
    {
        [$certDer, $keyPair] = $this->buildLeafCertificate('attest.example.com');

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('CN does not match attest.android.com');

        $this->verifyStatement(['response' => $this->jws(['alg' => 'RS256', 'x5c' => [base64_encode($certDer)]], $this->validPayload(), $keyPair)]);
    }

    public function test_rejects_a_signature_from_another_key(): void
    {
        [$certDer] = $this->buildLeafCertificate();
        [, $otherKey] = $this->buildLeafCertificate();

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('JWS signature verification failed');

        $this->verifyStatement(['response' => $this->jws(['alg' => 'RS256', 'x5c' => [base64_encode($certDer)]], $this->validPayload(), $otherKey)]);
    }

    public function test_rejects_a_segment_that_is_not_json(): void
    {
        [, $keyPair] = $this->buildLeafCertificate();

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('not valid JSON');

        $this->verifyStatement(['response' => $this->jws($this->base64Url('{not json'), $this->validPayload(), $keyPair)]);
    }

    public function test_rejects_a_segment_that_decodes_to_a_scalar(): void
    {
        [, $keyPair] = $this->buildLeafCertificate();

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('must decode to an object');

        $this->verifyStatement(['response' => $this->jws($this->base64Url('"just a string"'), $this->validPayload(), $keyPair)]);
    }

    public function test_rejects_a_segment_that_decodes_to_a_list(): void
    {
        [, $keyPair] = $this->buildLeafCertificate();

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('must decode to an object');

        $this->verifyStatement(['response' => $this->jws(['alg' => 'RS256'], $this->base64Url('[1,2,3]'), $keyPair)]);
    }

    public function test_rejects_a_segment_that_is_not_base64url(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('not valid base64url');

        $this->verifyStatement(['response' => 'a!b.c.d']);
    }
}
