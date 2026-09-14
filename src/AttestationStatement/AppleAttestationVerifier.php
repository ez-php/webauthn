<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

use EzPhp\WebAuthn\Asn1\Asn1Reader;
use EzPhp\WebAuthn\AuthenticatorData;
use EzPhp\WebAuthn\Cose\CoseKey;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;

/**
 * Verifies the "apple" attestation format (WebAuthn spec §8.8): no
 * signature at all — authenticity rests on the presented certificate's
 * chain to Apple's root (out of scope, no network calls). This verifier
 * checks only what's checkable without that chain: the nonce extension
 * binds the certificate to this ceremony, and the certificate's own public
 * key must match the credential's. See this plan's Task 6 for why
 * AttestationResult::$trusted is false for this format specifically.
 *
 * @package EzPhp\WebAuthn\AttestationStatement
 */
final class AppleAttestationVerifier implements AttestationStatementVerifierInterface
{
    private const string NONCE_EXTENSION_OID = '1.2.840.113635.100.8.2';

    public function verify(AttestationStatement $statement, string $authenticatorData, string $clientDataHash): AttestationResult
    {
        $x5c = $statement->attStmt['x5c'] ?? null;

        if (!is_array($x5c) || !isset($x5c[0]) || !is_string($x5c[0])) {
            throw new AttestationVerificationException('"apple" attestation statement is missing x5c.');
        }

        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($x5c[0]), 64, "\n") . "-----END CERTIFICATE-----\n";

        $expectedNonce = hash('sha256', $authenticatorData . $clientDataHash, true);
        $actualNonce = $this->extractNonce($pem);

        if (!hash_equals($expectedNonce, $actualNonce)) {
            throw new AttestationVerificationException('Apple attestation nonce does not match the expected attestation hash.');
        }

        $credentialKey = AuthenticatorData::parse($authenticatorData)->credentialPublicKey;

        if ($credentialKey === null) {
            throw new AttestationVerificationException('"apple" attestation requires attested credential data.');
        }

        $this->assertCertificateKeyMatchesCredential($pem, $credentialKey);

        return new AttestationResult(trusted: false, attestationType: 'apple');
    }

    private function extractNonce(string $certificatePem): string
    {
        $parsed = openssl_x509_parse($certificatePem, true);

        if ($parsed === false) {
            throw new AttestationVerificationException('Could not parse the Apple credCert.');
        }

        /** @var array{extensions?: array<string, string>} $parsed */
        $extensionValue = $parsed['extensions'][self::NONCE_EXTENSION_OID] ?? null;

        if (!is_string($extensionValue)) {
            throw new AttestationVerificationException('Apple credCert is missing the nonce extension.');
        }

        $elements = Asn1Reader::readSequenceElements($extensionValue);

        if (!isset($elements[0])) {
            throw new AttestationVerificationException('Apple nonce extension is malformed.');
        }

        $inner = Asn1Reader::readTlv($elements[0]['value'], 0);

        return $inner['value'];
    }

    private function assertCertificateKeyMatchesCredential(string $certificatePem, CoseKey $credentialKey): void
    {
        $publicKey = openssl_pkey_get_public($certificatePem);

        if ($publicKey === false) {
            throw new AttestationVerificationException('Could not read the Apple credCert public key.');
        }

        $details = openssl_pkey_get_details($publicKey);

        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC) {
            throw new AttestationVerificationException('Apple credCert key type is not supported (EC only).');
        }

        /** @var array{ec: array{x: string, y: string}} $details */
        $x = $credentialKey->parameters[-2] ?? null;
        $y = $credentialKey->parameters[-3] ?? null;
        $certX = $details['ec']['x'];
        $certY = $details['ec']['y'];

        if (!is_string($x) || !is_string($y)
            || !hash_equals(str_pad($x, 32, "\x00", STR_PAD_LEFT), str_pad($certX, 32, "\x00", STR_PAD_LEFT))
            || !hash_equals(str_pad($y, 32, "\x00", STR_PAD_LEFT), str_pad($certY, 32, "\x00", STR_PAD_LEFT))
        ) {
            throw new AttestationVerificationException('Apple credCert public key does not match the credential public key.');
        }
    }
}
