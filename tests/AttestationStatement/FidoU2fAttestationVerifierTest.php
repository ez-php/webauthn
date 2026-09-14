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
        // openssl_pkey_get_details() strips a coordinate's leading zero byte
        // rather than zero-padding to the curve's fixed field size, so it can
        // return fewer than 32 bytes for P-256 — pad back to the fixed-length
        // wire format a real authenticator emits (RFC 9053).
        $x = str_pad($x, 32, "\x00", STR_PAD_LEFT);
        $y = str_pad($y, 32, "\x00", STR_PAD_LEFT);
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
        // Pad to the fixed 32-byte field size before use: the verifier signs
        // over the coordinates as stored in the (now zero-padded, see
        // authenticatorDataWithCredential()) COSE key, so the raw
        // openssl_pkey_get_details() bytes — occasionally shorter, with a
        // leading zero byte stripped — must match that padding here too, or
        // the reconstructed U2F signed data diverges from what was signed.
        $x = str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT);
        $y = str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT);

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

    public function test_wraps_an_authenticator_data_parse_failure(): void
    {
        $verifier = new FidoU2fAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'fido-u2f', attStmt: ['sig' => 'not-a-real-signature', 'x5c' => ['not-a-real-cert']]);

        $this->expectException(AttestationVerificationException::class);

        // Too short to be valid authenticatorData (must be >= 37 bytes) —
        // AuthenticatorData::parse() throws \InvalidArgumentException, which
        // verify() must translate to this module's own exception type rather
        // than let escape untranslated.
        $verifier->verify($statement, 'too-short', hash('sha256', 'client-data', true));
    }
}
