<?php

declare(strict_types=1);

namespace Tests\AttestationStatement;

use EzPhp\WebAuthn\AttestationStatement\AndroidKeyAttestationVerifier;
use EzPhp\WebAuthn\AttestationStatement\AttestationStatement;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;
use Tests\TestCase;

/**
 * Class AndroidKeyAttestationVerifierTest
 *
 * @package Tests\AttestationStatement
 */
final class AndroidKeyAttestationVerifierTest extends TestCase
{
    private function authenticatorDataWithCredential(string $x, string $y): string
    {
        $rpIdHash = hash('sha256', 'example.com', true);
        $flags = "\x45";
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
        $coseKey = "\xa5\x01\x02\x03\x26\x20\x01" . "\x21\x58\x20" . $x . "\x22\x58\x20" . $y;

        return $rpIdHash . $flags . $signCount . $aaguid . $credentialIdLength . $credentialId . $coseKey;
    }

    /**
     * Builds a minimal DER KeyDescription SEQUENCE with $challenge as the
     * 5th element (attestationChallenge, index 4).
     */
    private function buildKeyDescription(string $challenge): string
    {
        $int3 = "\x02\x01\x03";       // INTEGER 3 (attestationVersion)
        $enum0 = "\x0a\x01\x00";      // ENUMERATED 0 (attestationSecurityLevel) — tag 0x0a
        $challengeElement = "\x04" . chr(strlen($challenge) & 0xff) . $challenge; // OCTET STRING
        $emptyOctetString = "\x04\x00";
        $emptySequence = "\x30\x00";

        $content = $int3 . $enum0 . $int3 . $enum0 . $challengeElement . $emptyOctetString . $emptySequence . $emptySequence;

        return "\x30" . chr(strlen($content) & 0xff) . $content;
    }

    /**
     * Builds a self-signed EC certificate carrying the Android key
     * attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) with
     * $attestationChallenge embedded at its expected element index, via a
     * temporary openssl.cnf (confirmed empirically to round-trip through
     * openssl_x509_parse() as the exact raw DER bytes — see this task's
     * description). Returns [certificateDer, $keyPair].
     *
     * @return array{0: string, 1: \OpenSSLAsymmetricKey}
     */
    private function buildLeafCertificate(string $attestationChallenge): array
    {
        $keyDescription = $this->buildKeyDescription($attestationChallenge);

        $configPath = tempnam(sys_get_temp_dir(), 'webauthn-androidkey-cnf');
        self::assertIsString($configPath);
        $config = "[req]\ndistinguished_name = dn\n[dn]\n[v3_ext]\n1.3.6.1.4.1.11129.2.1.17=critical,DER:" . bin2hex($keyDescription) . "\n";
        file_put_contents($configPath, $config);

        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);
        $csr = openssl_csr_new(['commonName' => 'Test Android Key Attestation'], $keyPair, ['digest_alg' => 'sha256', 'config' => $configPath]);
        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);
        $cert = openssl_csr_sign($csr, null, $keyPair, 1, ['digest_alg' => 'sha256', 'config' => $configPath, 'x509_extensions' => 'v3_ext']);
        self::assertNotFalse($cert);
        openssl_x509_export($cert, $certPem);
        self::assertIsString($certPem);
        $der = base64_decode(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n"], '', $certPem), strict: true);
        self::assertIsString($der);

        unlink($configPath);

        return [$der, $keyPair];
    }

    public function test_verifies_a_valid_android_key_attestation(): void
    {
        $clientDataHash = hash('sha256', 'client-data', true);
        [$der, $keyPair] = $this->buildLeafCertificate($clientDataHash);

        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $authenticatorData = $this->authenticatorDataWithCredential($details['ec']['x'], $details['ec']['y']);

        openssl_sign($authenticatorData . $clientDataHash, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $verifier = new AndroidKeyAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'android-key', attStmt: [
            'alg' => -7,
            'sig' => $signature,
            'x5c' => [$der],
        ]);

        $result = $verifier->verify($statement, $authenticatorData, $clientDataHash);

        self::assertTrue($result->trusted);
        self::assertSame('basic', $result->attestationType);
    }

    public function test_rejects_an_attestation_challenge_mismatch(): void
    {
        $clientDataHash = hash('sha256', 'client-data', true);
        [$der, $keyPair] = $this->buildLeafCertificate(str_repeat("\xff", 32)); // wrong challenge

        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $authenticatorData = $this->authenticatorDataWithCredential($details['ec']['x'], $details['ec']['y']);

        openssl_sign($authenticatorData . $clientDataHash, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $verifier = new AndroidKeyAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'android-key', attStmt: [
            'alg' => -7,
            'sig' => $signature,
            'x5c' => [$der],
        ]);

        $this->expectException(AttestationVerificationException::class);

        $verifier->verify($statement, $authenticatorData, $clientDataHash);
    }

    public function test_rejects_an_invalid_signature(): void
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);
        $csr = openssl_csr_new(['commonName' => 'Test Android Key Attestation'], $keyPair, ['digest_alg' => 'sha256']);
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
        $authenticatorData = $this->authenticatorDataWithCredential($details['ec']['x'], $details['ec']['y']);

        $verifier = new AndroidKeyAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'android-key', attStmt: [
            'alg' => -7,
            'sig' => 'not-a-real-signature',
            'x5c' => [$der],
        ]);

        $this->expectException(AttestationVerificationException::class);

        $verifier->verify($statement, $authenticatorData, hash('sha256', 'client-data', true));
    }
}
