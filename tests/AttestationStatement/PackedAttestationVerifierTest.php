<?php

declare(strict_types=1);

namespace Tests\AttestationStatement;

use EzPhp\WebAuthn\AttestationStatement\AttestationStatement;
use EzPhp\WebAuthn\AttestationStatement\PackedAttestationVerifier;
use EzPhp\WebAuthn\Cose\Verifier\EdDsaVerifier;
use EzPhp\WebAuthn\Cose\Verifier\Es256Verifier;
use EzPhp\WebAuthn\Cose\Verifier\Rs256Verifier;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;
use Tests\TestCase;

/**
 * Class PackedAttestationVerifierTest
 *
 * @package Tests\AttestationStatement
 */
final class PackedAttestationVerifierTest extends TestCase
{
    /**
     * @return array<int, \EzPhp\WebAuthn\Cose\SignatureVerifierInterface>
     */
    private function verifiers(): array
    {
        return [-7 => new Es256Verifier(), -257 => new Rs256Verifier(), -8 => new EdDsaVerifier()];
    }

    /**
     * Builds a real (minimal) authenticatorData byte string with attested
     * credential data carrying an ES256 COSE key built from real EC
     * coordinates — same binary layout AuthenticatorDataTest (Task 8) covers.
     */
    private function authenticatorDataWithCredential(string $x, string $y): string
    {
        $rpIdHash = hash('sha256', 'example.com', true);
        $flags = "\x45"; // UP=1, UV=1, AT=1
        $signCount = "\x00\x00\x00\x01";
        $aaguid = str_repeat("\x00", 16);
        $credentialId = str_repeat("\xaa", 16);
        $credentialIdLength = pack('n', strlen($credentialId));
        // openssl_pkey_get_details() strips a coordinate's leading zero byte
        // rather than zero-padding to the curve's fixed field size, so it can
        // return fewer than 32 bytes for P-256 — pad back to the fixed-length
        // wire format a real authenticator emits (RFC 9053).
        $x = str_pad($x, 32, "\x00", STR_PAD_LEFT);
        $y = str_pad($y, 32, "\x00", STR_PAD_LEFT);
        // COSE_Key map: {1: 2 (kty=EC2), 3: -7 (alg=ES256), -1: 1 (crv=P-256), -2: x, -3: y}
        $coseKey = "\xa5\x01\x02\x03\x26\x20\x01"
            . "\x21\x58\x20" . $x
            . "\x22\x58\x20" . $y;

        return $rpIdHash . $flags . $signCount . $aaguid . $credentialIdLength . $credentialId . $coseKey;
    }

    public function test_verifies_self_attestation(): void
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);
        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $x = $details['ec']['x'];
        $y = $details['ec']['y'];

        $authenticatorData = $this->authenticatorDataWithCredential($x, $y);
        $clientDataHash = 'fake-client-data-hash';
        openssl_sign($authenticatorData . $clientDataHash, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $verifier = new PackedAttestationVerifier($this->verifiers());
        $statement = new AttestationStatement(fmt: 'packed', attStmt: ['alg' => -7, 'sig' => $signature]);

        $result = $verifier->verify($statement, $authenticatorData, $clientDataHash);

        self::assertSame('self', $result->attestationType);
        self::assertFalse($result->trusted);
    }

    public function test_verifies_full_attestation_via_x5c_leaf_certificate(): void
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);

        $csr = openssl_csr_new(['commonName' => 'Test Authenticator'], $keyPair, ['digest_alg' => 'sha256']);
        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);
        $cert = openssl_csr_sign($csr, null, $keyPair, 1, ['digest_alg' => 'sha256']);
        self::assertNotFalse($cert);
        openssl_x509_export($cert, $certPem);
        self::assertIsString($certPem);

        // Strip PEM headers/newlines to get the raw DER bytes x5c carries.
        $der = base64_decode(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n"], '', $certPem), strict: true);
        self::assertIsString($der);

        // Credential key deliberately differs from the attestation cert's
        // signing key, as is normal for full (non-self) attestation.
        $credentialKeyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($credentialKeyPair);
        $credentialDetails = openssl_pkey_get_details($credentialKeyPair);
        self::assertIsArray($credentialDetails);
        /** @var array{ec: array{x: string, y: string}} $credentialDetails */
        $authenticatorData = $this->authenticatorDataWithCredential($credentialDetails['ec']['x'], $credentialDetails['ec']['y']);

        $clientDataHash = 'fake-client-data-hash';
        openssl_sign($authenticatorData . $clientDataHash, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $verifier = new PackedAttestationVerifier($this->verifiers());
        $statement = new AttestationStatement(fmt: 'packed', attStmt: ['alg' => -7, 'sig' => $signature, 'x5c' => [$der]]);

        $result = $verifier->verify($statement, $authenticatorData, $clientDataHash);

        self::assertSame('basic', $result->attestationType);
        self::assertTrue($result->trusted);
    }

    public function test_rejects_an_invalid_self_attestation_signature(): void
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);
        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $authenticatorData = $this->authenticatorDataWithCredential($details['ec']['x'], $details['ec']['y']);

        $verifier = new PackedAttestationVerifier($this->verifiers());
        $statement = new AttestationStatement(fmt: 'packed', attStmt: ['alg' => -7, 'sig' => 'not-a-real-signature']);

        $this->expectException(AttestationVerificationException::class);

        $verifier->verify($statement, $authenticatorData, 'client-data-hash');
    }

    public function test_wraps_an_authenticator_data_parse_failure_in_self_attestation(): void
    {
        $verifier = new PackedAttestationVerifier($this->verifiers());
        $statement = new AttestationStatement(fmt: 'packed', attStmt: ['alg' => -7, 'sig' => 'not-a-real-signature']);

        $this->expectException(AttestationVerificationException::class);

        // Too short to be valid authenticatorData (must be >= 37 bytes) —
        // AuthenticatorData::parse() throws \InvalidArgumentException, which
        // self-attestation must translate to this module's own exception
        // type rather than let escape untranslated.
        $verifier->verify($statement, 'too-short', 'client-data-hash');
    }
}
