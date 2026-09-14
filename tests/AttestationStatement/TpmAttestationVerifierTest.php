<?php

declare(strict_types=1);

namespace Tests\AttestationStatement;

use EzPhp\WebAuthn\AttestationStatement\AttestationStatement;
use EzPhp\WebAuthn\AttestationStatement\TpmAttestationVerifier;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;
use Tests\TestCase;

/**
 * Class TpmAttestationVerifierTest
 *
 * @package Tests\AttestationStatement
 */
final class TpmAttestationVerifierTest extends TestCase
{
    private function packUint16(int $value): string
    {
        return pack('n', $value);
    }

    /**
     * Real (minimal) authenticatorData carrying an ES256 credential, built
     * the same way Phase 1's PackedAttestationVerifierTest does.
     */
    private function authenticatorDataWithCredential(string $x, string $y): string
    {
        $rpIdHash = hash('sha256', 'example.com', true);
        $flags = "\x45";
        $signCount = "\x00\x00\x00\x01";
        $aaguid = str_repeat("\x00", 16);
        $credentialId = str_repeat("\xaa", 16);
        $credentialIdLength = $this->packUint16(strlen($credentialId));
        // openssl_pkey_get_details() strips a coordinate's leading zero byte
        // rather than zero-padding to the curve's fixed field size, so it can
        // return fewer than 32 bytes for P-256 — pad back to the fixed-length
        // wire format a real authenticator emits (RFC 9053).
        $x = str_pad($x, 32, "\x00", STR_PAD_LEFT);
        $y = str_pad($y, 32, "\x00", STR_PAD_LEFT);
        $coseKey = "\xa5\x01\x02\x03\x26\x20\x01" . "\x21\x58\x20" . $x . "\x22\x58\x20" . $y;

        return $rpIdHash . $flags . $signCount . $aaguid . $credentialIdLength . $credentialId . $coseKey;
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

    private function buildCertInfo(string $extraData): string
    {
        $nameAlgId = "\x00\x0b";
        $nameHash = hash('sha256', $this->buildPubArea(str_repeat("\x01", 32), str_repeat("\x02", 32)), true);
        $name = $nameAlgId . $nameHash;
        $clockInfo = str_repeat("\x00", 17);
        $firmwareVersion = str_repeat("\x00", 8);

        return pack('N', 0xff544347)
            . $this->packUint16(0x8017)
            . $this->packUint16(0)
            . $this->packUint16(strlen($extraData)) . $extraData
            . $clockInfo
            . $firmwareVersion
            . $this->packUint16(strlen($name)) . $name
            . $this->packUint16(0);
    }

    public function test_verifies_a_valid_tpm_attestation(): void
    {
        $x = str_repeat("\x01", 32);
        $y = str_repeat("\x02", 32);
        $authenticatorData = $this->authenticatorDataWithCredential($x, $y);
        $clientDataHash = hash('sha256', 'client-data', true);
        $pubArea = $this->buildPubArea($x, $y);
        $extraData = hash('sha256', $authenticatorData . $clientDataHash, true);
        $certInfo = $this->buildCertInfo($extraData);

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

        openssl_sign($certInfo, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $verifier = new TpmAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'tpm', attStmt: [
            'ver' => '2.0',
            'alg' => -7,
            'sig' => $signature,
            'certInfo' => $certInfo,
            'pubArea' => $pubArea,
            'x5c' => [$der],
        ]);

        $result = $verifier->verify($statement, $authenticatorData, $clientDataHash);

        self::assertTrue($result->trusted);
        self::assertSame('attca', $result->attestationType);
    }

    public function test_rejects_a_pub_area_that_does_not_match_the_credential(): void
    {
        $authenticatorData = $this->authenticatorDataWithCredential(str_repeat("\x01", 32), str_repeat("\x02", 32));
        $clientDataHash = hash('sha256', 'client-data', true);
        // pubArea uses different coordinates than the credential.
        $pubArea = $this->buildPubArea(str_repeat("\x09", 32), str_repeat("\x08", 32));
        $certInfo = $this->buildCertInfo(hash('sha256', $authenticatorData . $clientDataHash, true));

        $verifier = new TpmAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'tpm', attStmt: [
            'ver' => '2.0',
            'alg' => -7,
            'sig' => 'irrelevant',
            'certInfo' => $certInfo,
            'pubArea' => $pubArea,
            'x5c' => ['irrelevant'],
        ]);

        $this->expectException(AttestationVerificationException::class);

        $verifier->verify($statement, $authenticatorData, $clientDataHash);
    }

    public function test_rejects_extra_data_mismatch(): void
    {
        $x = str_repeat("\x01", 32);
        $y = str_repeat("\x02", 32);
        $authenticatorData = $this->authenticatorDataWithCredential($x, $y);
        $pubArea = $this->buildPubArea($x, $y);
        $certInfo = $this->buildCertInfo(str_repeat("\xff", 32)); // wrong extraData

        $verifier = new TpmAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'tpm', attStmt: [
            'ver' => '2.0',
            'alg' => -7,
            'sig' => 'irrelevant',
            'certInfo' => $certInfo,
            'pubArea' => $pubArea,
            'x5c' => ['irrelevant'],
        ]);

        $this->expectException(AttestationVerificationException::class);

        $verifier->verify($statement, $authenticatorData, hash('sha256', 'client-data', true));
    }

    public function test_wraps_an_authenticator_data_parse_failure(): void
    {
        $verifier = new TpmAttestationVerifier();
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
        $verifier->verify($statement, 'too-short', hash('sha256', 'client-data', true));
    }
}
