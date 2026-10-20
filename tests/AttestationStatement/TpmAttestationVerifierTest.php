<?php

declare(strict_types=1);

namespace Tests\AttestationStatement;

use EzPhp\WebAuthn\AttestationStatement\AttestationStatement;
use EzPhp\WebAuthn\AttestationStatement\TpmAttestationVerifier;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;
use OpenSSLAsymmetricKey;
use Tests\TestCase;

/**
 * Class TpmAttestationVerifierTest
 *
 * Every check `verify()` performs gets its own rejection test, built from a
 * valid synthetic attestation with exactly one part broken.
 *
 * @package Tests\AttestationStatement
 */
final class TpmAttestationVerifierTest extends TestCase
{
    private const string X = "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

    private const string Y = "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02";

    private const int TPM_GENERATED_VALUE = 0xff544347;

    private const int TPM_ST_ATTEST_CERTIFY = 0x8017;

    private const string SHA256_ALG_ID = "\x00\x0b";

    private function packUint16(int $value): string
    {
        return pack('n', $value);
    }

    /**
     * authenticatorData carrying an attested credential with the given COSE key.
     */
    private function authenticatorDataWithKey(string $coseKey): string
    {
        $rpIdHash = hash('sha256', 'example.com', true);
        $credentialId = str_repeat("\xaa", 16);

        return $rpIdHash . "\x45" . "\x00\x00\x00\x01" . str_repeat("\x00", 16)
            . $this->packUint16(strlen($credentialId)) . $credentialId . $coseKey;
    }

    /**
     * authenticatorData carrying an ES256 credential, built the same way
     * Phase 1's PackedAttestationVerifierTest does.
     */
    private function authenticatorDataWithCredential(string $x, string $y): string
    {
        // openssl_pkey_get_details() strips a coordinate's leading zero byte
        // rather than zero-padding to the curve's fixed field size, so it can
        // return fewer than 32 bytes for P-256 — pad back to the fixed-length
        // wire format a real authenticator emits (RFC 9053).
        $x = str_pad($x, 32, "\x00", STR_PAD_LEFT);
        $y = str_pad($y, 32, "\x00", STR_PAD_LEFT);

        return $this->authenticatorDataWithKey("\xa5\x01\x02\x03\x26\x20\x01" . "\x21\x58\x20" . $x . "\x22\x58\x20" . $y);
    }

    /**
     * authenticatorData carrying an RS256 credential (kty 3, alg -257).
     */
    private function authenticatorDataWithRsaCredential(string $modulus, string $exponent): string
    {
        $coseKey = "\xa4\x01\x03\x03\x39\x01\x00"
            . "\x20\x59" . $this->packUint16(strlen($modulus)) . $modulus
            . "\x21\x43" . $exponent;

        return $this->authenticatorDataWithKey($coseKey);
    }

    private function buildPubArea(string $x, string $y): string
    {
        return $this->packUint16(0x0023)
            . $this->packUint16(0x000b)
            . pack('N', 0)
            . $this->packUint16(0)
            . $this->packUint16(0x0010)
            . $this->packUint16(0x0010)
            . $this->packUint16(0x0003)
            . $this->packUint16(0x0010)
            . $this->packUint16(strlen($x)) . $x
            . $this->packUint16(strlen($y)) . $y;
    }

    private function buildRsaPubArea(string $modulus, int $exponent): string
    {
        return $this->packUint16(0x0001)
            . $this->packUint16(0x000b)
            . pack('N', 0)
            . $this->packUint16(0)
            . $this->packUint16(0x0010)
            . $this->packUint16(0x0010)
            . $this->packUint16(strlen($modulus) * 8)
            . pack('N', $exponent)
            . $this->packUint16(strlen($modulus)) . $modulus;
    }

    private function buildCertInfo(
        string $extraData,
        string $pubArea,
        int $magic = self::TPM_GENERATED_VALUE,
        int $type = self::TPM_ST_ATTEST_CERTIFY,
        string $nameAlgId = self::SHA256_ALG_ID,
    ): string {
        $name = $nameAlgId . hash('sha256', $pubArea, true);

        return pack('N', $magic)
            . $this->packUint16($type)
            . $this->packUint16(0)
            . $this->packUint16(strlen($extraData)) . $extraData
            . str_repeat("\x00", 17)
            . str_repeat("\x00", 8)
            . $this->packUint16(strlen($name)) . $name
            . $this->packUint16(0);
    }

    /**
     * @return array{OpenSSLAsymmetricKey, string} The AIK key pair and its self-signed DER certificate.
     */
    private function aik(): array
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);
        $csr = openssl_csr_new(['commonName' => 'Test AIK'], $keyPair, ['digest_alg' => 'sha256']);
        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);
        $cert = openssl_csr_sign($csr, null, $keyPair, 1, ['digest_alg' => 'sha256']);
        self::assertNotFalse($cert);
        openssl_x509_export($cert, $certPem);
        self::assertIsString($certPem);
        $der = base64_decode(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n"], '', $certPem), strict: true);
        self::assertIsString($der);

        return [$keyPair, $der];
    }

    /**
     * A complete, correctly signed attStmt for the given parts.
     *
     * @param array<string, mixed> $overrides attStmt fields to replace after signing
     *
     * @return array<string, mixed>
     */
    private function signedAttStmt(string $certInfo, string $pubArea, array $overrides = []): array
    {
        [$keyPair, $der] = $this->aik();
        openssl_sign($certInfo, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        return array_replace([
            'ver' => '2.0',
            'alg' => -7,
            'sig' => $signature,
            'certInfo' => $certInfo,
            'pubArea' => $pubArea,
            'x5c' => [$der],
        ], $overrides);
    }

    /**
     * The valid EC scenario with one field overridden, run through verify().
     *
     * @param array<string, mixed> $overrides
     */
    private function verifyEcWith(array $overrides = [], ?string $certInfo = null): void
    {
        $authenticatorData = $this->authenticatorDataWithCredential(self::X, self::Y);
        $clientDataHash = hash('sha256', 'client-data', true);
        $pubArea = $this->buildPubArea(self::X, self::Y);
        $certInfo ??= $this->buildCertInfo(hash('sha256', $authenticatorData . $clientDataHash, true), $pubArea);

        (new TpmAttestationVerifier())->verify(
            new AttestationStatement(fmt: 'tpm', attStmt: $this->signedAttStmt($certInfo, $pubArea, $overrides)),
            $authenticatorData,
            $clientDataHash,
        );
    }

    private function ecCertInfo(int $magic = self::TPM_GENERATED_VALUE, int $type = self::TPM_ST_ATTEST_CERTIFY, string $nameAlgId = self::SHA256_ALG_ID, ?string $namedPubArea = null): string
    {
        $authenticatorData = $this->authenticatorDataWithCredential(self::X, self::Y);
        $extraData = hash('sha256', $authenticatorData . hash('sha256', 'client-data', true), true);

        return $this->buildCertInfo($extraData, $namedPubArea ?? $this->buildPubArea(self::X, self::Y), $magic, $type, $nameAlgId);
    }

    public function test_verifies_a_valid_tpm_attestation(): void
    {
        $authenticatorData = $this->authenticatorDataWithCredential(self::X, self::Y);
        $clientDataHash = hash('sha256', 'client-data', true);
        $pubArea = $this->buildPubArea(self::X, self::Y);
        $certInfo = $this->buildCertInfo(hash('sha256', $authenticatorData . $clientDataHash, true), $pubArea);

        $result = (new TpmAttestationVerifier())->verify(
            new AttestationStatement(fmt: 'tpm', attStmt: $this->signedAttStmt($certInfo, $pubArea)),
            $authenticatorData,
            $clientDataHash,
        );

        self::assertTrue($result->trusted);
        self::assertSame('attca', $result->attestationType);
    }

    public function test_verifies_an_rsa_credential_with_the_tpm_default_exponent(): void
    {
        $modulus = "\xc1" . str_repeat("\x5a", 255);
        $authenticatorData = $this->authenticatorDataWithRsaCredential($modulus, "\x01\x00\x01");
        $clientDataHash = hash('sha256', 'client-data', true);
        $pubArea = $this->buildRsaPubArea($modulus, 0); // 0 = the TPM's implied 65537
        $certInfo = $this->buildCertInfo(hash('sha256', $authenticatorData . $clientDataHash, true), $pubArea);

        $result = (new TpmAttestationVerifier())->verify(
            new AttestationStatement(fmt: 'tpm', attStmt: $this->signedAttStmt($certInfo, $pubArea)),
            $authenticatorData,
            $clientDataHash,
        );

        self::assertTrue($result->trusted);
    }

    public function test_rejects_an_rsa_modulus_that_does_not_match_the_credential(): void
    {
        $authenticatorData = $this->authenticatorDataWithRsaCredential("\xc1" . str_repeat("\x5a", 255), "\x01\x00\x01");
        $pubArea = $this->buildRsaPubArea("\xc1" . str_repeat("\x5b", 255), 65537);

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('RSA modulus does not match');

        (new TpmAttestationVerifier())->verify(
            new AttestationStatement(fmt: 'tpm', attStmt: $this->signedAttStmt('irrelevant', $pubArea)),
            $authenticatorData,
            hash('sha256', 'client-data', true),
        );
    }

    public function test_rejects_an_rsa_exponent_that_does_not_match_the_credential(): void
    {
        $modulus = "\xc1" . str_repeat("\x5a", 255);
        $authenticatorData = $this->authenticatorDataWithRsaCredential($modulus, "\x01\x00\x01");
        $pubArea = $this->buildRsaPubArea($modulus, 3);

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('RSA exponent does not match');

        (new TpmAttestationVerifier())->verify(
            new AttestationStatement(fmt: 'tpm', attStmt: $this->signedAttStmt('irrelevant', $pubArea)),
            $authenticatorData,
            hash('sha256', 'client-data', true),
        );
    }

    public function test_rejects_a_statement_with_missing_fields(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('missing required fields');

        $this->verifyEcWith(['ver' => '1.0']);
    }

    public function test_rejects_authenticator_data_without_attested_credential_data(): void
    {
        $authenticatorData = hash('sha256', 'example.com', true) . "\x01" . "\x00\x00\x00\x01";

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('requires attested credential data');

        (new TpmAttestationVerifier())->verify(
            new AttestationStatement(fmt: 'tpm', attStmt: $this->signedAttStmt('irrelevant', 'irrelevant')),
            $authenticatorData,
            hash('sha256', 'client-data', true),
        );
    }

    public function test_wraps_a_malformed_pub_area(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('could not parse pubArea');

        $this->verifyEcWith(['pubArea' => "\x00\x23"]);
    }

    public function test_wraps_a_malformed_cert_info(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('could not parse certInfo');

        $this->verifyEcWith(certInfo: "\xff\x54");
    }

    public function test_rejects_a_wrong_magic_value(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('magic does not match');

        $this->verifyEcWith(certInfo: $this->ecCertInfo(magic: 0x12345678));
    }

    public function test_rejects_a_wrong_attestation_type(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('type does not match');

        $this->verifyEcWith(certInfo: $this->ecCertInfo(type: 0x8018));
    }

    public function test_rejects_extra_data_mismatch(): void
    {
        $pubArea = $this->buildPubArea(self::X, self::Y);

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('extraData does not match');

        $this->verifyEcWith(certInfo: $this->buildCertInfo(str_repeat("\xff", 32), $pubArea));
    }

    public function test_rejects_an_unsupported_name_algorithm(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('unsupported hash algorithm');

        $this->verifyEcWith(certInfo: $this->ecCertInfo(nameAlgId: "\x00\x04"));
    }

    public function test_rejects_a_name_that_does_not_hash_the_pub_area(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('name does not match the hash of pubArea');

        $this->verifyEcWith(certInfo: $this->ecCertInfo(namedPubArea: 'some other pubArea'));
    }

    public function test_rejects_an_unreadable_aik_certificate(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage("AIK certificate's public key");

        $this->verifyEcWith(['x5c' => ['not a certificate']]);
    }

    public function test_rejects_an_unsupported_signature_algorithm(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('Unsupported COSE algorithm for tpm attestation: -8');

        $this->verifyEcWith(['alg' => -8]);
    }

    public function test_rejects_a_signature_that_does_not_verify(): void
    {
        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('signature verification failed');

        $this->verifyEcWith(['sig' => str_repeat("\x30", 70)]);
    }

    public function test_rejects_a_pub_area_that_does_not_match_the_credential(): void
    {
        $authenticatorData = $this->authenticatorDataWithCredential(self::X, self::Y);
        // pubArea uses different coordinates than the credential.
        $pubArea = $this->buildPubArea(str_repeat("\x09", 32), str_repeat("\x08", 32));

        $this->expectException(AttestationVerificationException::class);
        $this->expectExceptionMessage('EC coordinates do not match');

        (new TpmAttestationVerifier())->verify(
            new AttestationStatement(fmt: 'tpm', attStmt: $this->signedAttStmt('irrelevant', $pubArea)),
            $authenticatorData,
            hash('sha256', 'client-data', true),
        );
    }

    public function test_wraps_an_authenticator_data_parse_failure(): void
    {
        $statement = new AttestationStatement(fmt: 'tpm', attStmt: [
            'ver' => '2.0',
            'alg' => -7,
            'sig' => 'irrelevant',
            'certInfo' => 'irrelevant',
            'pubArea' => 'irrelevant',
            'x5c' => ['irrelevant'],
        ]);

        $this->expectException(AttestationVerificationException::class);

        // Too short to be valid authenticatorData (must be >= 37 bytes) —
        // AuthenticatorData::parse() throws \InvalidArgumentException, which
        // verify() must translate to this module's own exception type rather
        // than let escape untranslated.
        (new TpmAttestationVerifier())->verify($statement, 'too-short', hash('sha256', 'client-data', true));
    }
}
