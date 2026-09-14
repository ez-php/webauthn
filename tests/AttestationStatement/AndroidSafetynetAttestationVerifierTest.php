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
    private function buildLeafCertificate(): array
    {
        $keyPair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($keyPair);
        $csr = openssl_csr_new(['commonName' => 'attest.android.com'], $keyPair, ['digest_alg' => 'sha256']);
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
}
