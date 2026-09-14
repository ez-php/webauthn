<?php

declare(strict_types=1);

namespace Tests\AttestationStatement;

use EzPhp\WebAuthn\AttestationStatement\AttestationStatement;
use EzPhp\WebAuthn\AttestationStatement\FidoU2fAttestationVerifier;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;
use Tests\TestCase;

/**
 * Class FidoU2fAttestationVerifierTest
 *
 * @package Tests\AttestationStatement
 */
final class FidoU2fAttestationVerifierTest extends TestCase
{
    /**
     * Builds a real (minimal) authenticatorData byte string with attested
     * credential data carrying an ES256 COSE key — same binary layout
     * AuthenticatorDataTest (Task 8) covers. Returns [authenticatorData, credentialId].
     *
     * @return array{0: string, 1: string}
     */
    private function authenticatorDataWithCredential(string $x, string $y): array
    {
        $rpIdHash = hash('sha256', 'example.com', true);
        $flags = "\x45"; // UP=1, UV=1, AT=1
        $signCount = "\x00\x00\x00\x01";
        $aaguid = str_repeat("\x00", 16);
        $credentialId = str_repeat("\xaa", 32);
        $credentialIdLength = pack('n', strlen($credentialId));
        $coseKey = "\xa5\x01\x02\x03\x26\x20\x01"
            . "\x21\x58\x20" . $x
            . "\x22\x58\x20" . $y;

        return [$rpIdHash . $flags . $signCount . $aaguid . $credentialIdLength . $credentialId . $coseKey, $credentialId];
    }

    public function test_verifies_a_valid_u2f_attestation(): void
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);

        $csr = openssl_csr_new(['commonName' => 'Test U2F Authenticator'], $keyPair, ['digest_alg' => 'sha256']);
        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);
        $cert = openssl_csr_sign($csr, null, $keyPair, 1, ['digest_alg' => 'sha256']);
        self::assertNotFalse($cert);
        openssl_x509_export($cert, $certPem);
        self::assertIsString($certPem);
        $der = base64_decode(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n"], '', $certPem), strict: true);
        self::assertIsString($der);

        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $x = $details['ec']['x'];
        $y = $details['ec']['y'];

        [$authenticatorData, $credentialId] = $this->authenticatorDataWithCredential($x, $y);
        $rpIdHash = hash('sha256', 'example.com', true);
        $clientDataHash = hash('sha256', 'client-data', true);

        $signedData = "\x00" . $rpIdHash . $clientDataHash . $credentialId . "\x04" . $x . $y;
        openssl_sign($signedData, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $verifier = new FidoU2fAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'fido-u2f', attStmt: ['sig' => $signature, 'x5c' => [$der]]);

        $result = $verifier->verify($statement, $authenticatorData, $clientDataHash);

        self::assertTrue($result->trusted);
        self::assertSame('basic', $result->attestationType);
    }

    public function test_rejects_an_invalid_signature(): void
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);
        $csr = openssl_csr_new(['commonName' => 'Test U2F Authenticator'], $keyPair, ['digest_alg' => 'sha256']);
        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);
        $cert = openssl_csr_sign($csr, null, $keyPair, 1, ['digest_alg' => 'sha256']);
        self::assertNotFalse($cert);
        openssl_x509_export($cert, $certPem);
        self::assertIsString($certPem);
        $der = base64_decode(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n"], '', $certPem), strict: true);
        self::assertIsString($der);

        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        [$authenticatorData] = $this->authenticatorDataWithCredential($details['ec']['x'], $details['ec']['y']);

        $verifier = new FidoU2fAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'fido-u2f', attStmt: ['sig' => 'not-a-real-signature', 'x5c' => [$der]]);

        $this->expectException(AttestationVerificationException::class);

        $verifier->verify($statement, $authenticatorData, hash('sha256', 'client-data', true));
    }
}
