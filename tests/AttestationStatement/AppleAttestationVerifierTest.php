<?php

declare(strict_types=1);

namespace Tests\AttestationStatement;

use EzPhp\WebAuthn\AttestationStatement\AppleAttestationVerifier;
use EzPhp\WebAuthn\AttestationStatement\AttestationStatement;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;
use Tests\TestCase;

/**
 * Class AppleAttestationVerifierTest
 *
 * @package Tests\AttestationStatement
 */
final class AppleAttestationVerifierTest extends TestCase
{
    private function authenticatorDataWithCredential(string $x, string $y): string
    {
        $rpIdHash = hash('sha256', 'example.com', true);
        $flags = "\x45";
        $signCount = "\x00\x00\x00\x01";
        $aaguid = str_repeat("\x00", 16);
        $credentialId = str_repeat("\xaa", 16);
        $credentialIdLength = pack('n', strlen($credentialId));
        $coseKey = "\xa5\x01\x02\x03\x26\x20\x01" . "\x21\x58\x20" . $x . "\x22\x58\x20" . $y;

        return $rpIdHash . $flags . $signCount . $aaguid . $credentialIdLength . $credentialId . $coseKey;
    }

    /**
     * Builds a self-signed EC certificate whose public key is exactly
     * ($x, $y), with the Apple nonce extension (OID 1.2.840.113635.100.8.2)
     * set to SEQUENCE { [1] { OCTET STRING $nonce } }, via a temporary
     * openssl.cnf. Takes an existing EC key pair (generate once in the
     * calling test, pass it here, then build authenticatorData from its own
     * x/y before computing the nonce and calling this method) — resolving
     * the ordering problem "the nonce depends on authenticatorData, which
     * depends on the cert's own key" by not generating the key inside this
     * method at all.
     */
    private function buildCredCert(\OpenSSLAsymmetricKey $keyPair, string $nonce): string
    {
        $octetString = "\x04" . chr(strlen($nonce) & 0xff) . $nonce;
        $explicitOne = "\xa1" . chr(strlen($octetString) & 0xff) . $octetString;
        $nonceExtensionValue = "\x30" . chr(strlen($explicitOne) & 0xff) . $explicitOne;

        $configPath = tempnam(sys_get_temp_dir(), 'webauthn-apple-cnf');
        self::assertIsString($configPath);
        $config = "[req]\ndistinguished_name = dn\n[dn]\n[v3_ext]\n1.2.840.113635.100.8.2=critical,DER:" . bin2hex($nonceExtensionValue) . "\n";
        file_put_contents($configPath, $config);

        $csr = openssl_csr_new(['commonName' => 'Test Apple Anonymous Attestation'], $keyPair, ['digest_alg' => 'sha256', 'config' => $configPath]);
        self::assertInstanceOf(\OpenSSLCertificateSigningRequest::class, $csr);
        $cert = openssl_csr_sign($csr, null, $keyPair, 1, ['digest_alg' => 'sha256', 'config' => $configPath, 'x509_extensions' => 'v3_ext']);
        self::assertNotFalse($cert);
        openssl_x509_export($cert, $certPem);
        self::assertIsString($certPem);
        $der = base64_decode(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n"], '', $certPem), strict: true);
        self::assertIsString($der);

        unlink($configPath);

        return $der;
    }

    public function test_verifies_a_valid_apple_attestation(): void
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);
        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $x = $details['ec']['x'];
        $y = $details['ec']['y'];

        $authenticatorData = $this->authenticatorDataWithCredential($x, $y);
        $clientDataHash = hash('sha256', 'client-data', true);
        $nonce = hash('sha256', $authenticatorData . $clientDataHash, true);

        $certDer = $this->buildCredCert($keyPair, $nonce);

        $verifier = new AppleAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'apple', attStmt: ['x5c' => [$certDer]]);

        $result = $verifier->verify($statement, $authenticatorData, $clientDataHash);

        self::assertFalse($result->trusted);
        self::assertSame('apple', $result->attestationType);
    }

    public function test_rejects_a_nonce_mismatch(): void
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);
        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $authenticatorData = $this->authenticatorDataWithCredential($details['ec']['x'], $details['ec']['y']);

        $certDer = $this->buildCredCert($keyPair, str_repeat("\xff", 32)); // wrong nonce

        $verifier = new AppleAttestationVerifier();
        $statement = new AttestationStatement(fmt: 'apple', attStmt: ['x5c' => [$certDer]]);

        $this->expectException(AttestationVerificationException::class);

        $verifier->verify($statement, $authenticatorData, hash('sha256', 'client-data', true));
    }
}
