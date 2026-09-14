<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

use EzPhp\WebAuthn\AuthenticatorData;
use EzPhp\WebAuthn\Cose\CoseKey;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;
use EzPhp\WebAuthn\Tpm\TpmsAttestParser;
use EzPhp\WebAuthn\Tpm\TpmtPublicKey;
use EzPhp\WebAuthn\Tpm\TpmtPublicParser;

/**
 * Verifies the "tpm" attestation format (WebAuthn spec §8.3). See this
 * plan's Task 3 description for the exact verification steps and the
 * documented scope limit (signature validity against the presented AIK
 * certificate only — no certificate-profile or chain-of-trust validation).
 *
 * @package EzPhp\WebAuthn\AttestationStatement
 */
final class TpmAttestationVerifier implements AttestationStatementVerifierInterface
{
    private const int TPM_GENERATED_VALUE = 0xff544347;
    private const int TPM_ST_ATTEST_CERTIFY = 0x8017;
    private const string TPM_ALG_SHA256_ID = "\x00\x0b";

    public function verify(AttestationStatement $statement, string $authenticatorData, string $clientDataHash): AttestationResult
    {
        $ver = $statement->attStmt['ver'] ?? null;
        $alg = $statement->attStmt['alg'] ?? null;
        $sig = $statement->attStmt['sig'] ?? null;
        $certInfoBytes = $statement->attStmt['certInfo'] ?? null;
        $pubAreaBytes = $statement->attStmt['pubArea'] ?? null;
        $x5c = $statement->attStmt['x5c'] ?? null;

        if ($ver !== '2.0' || !is_int($alg) || !is_string($sig) || !is_string($certInfoBytes)
            || !is_string($pubAreaBytes) || !is_array($x5c) || !isset($x5c[0]) || !is_string($x5c[0])
        ) {
            throw new AttestationVerificationException('"tpm" attestation statement is missing required fields.');
        }

        try {
            $credentialKey = AuthenticatorData::parse($authenticatorData)->credentialPublicKey;
        } catch (\InvalidArgumentException $e) {
            throw new AttestationVerificationException('"tpm" attestation could not parse authenticatorData: ' . $e->getMessage(), previous: $e);
        }

        if ($credentialKey === null) {
            throw new AttestationVerificationException('"tpm" attestation requires attested credential data.');
        }

        $pubArea = TpmtPublicParser::parse($pubAreaBytes);
        $this->assertPubAreaMatchesCredential($pubArea, $credentialKey);

        $certInfo = TpmsAttestParser::parse($certInfoBytes);

        if ($certInfo->magic !== self::TPM_GENERATED_VALUE) {
            throw new AttestationVerificationException('TPMS_ATTEST magic does not match TPM_GENERATED_VALUE.');
        }

        if ($certInfo->type !== self::TPM_ST_ATTEST_CERTIFY) {
            throw new AttestationVerificationException('TPMS_ATTEST type does not match TPM_ST_ATTEST_CERTIFY.');
        }

        $expectedExtraData = hash('sha256', $authenticatorData . $clientDataHash, true);

        if (!hash_equals($expectedExtraData, $certInfo->extraData)) {
            throw new AttestationVerificationException('TPMS_ATTEST extraData does not match the expected attestation hash.');
        }

        if ($certInfo->attestedNameAlgId !== self::TPM_ALG_SHA256_ID) {
            throw new AttestationVerificationException('TPMS_ATTEST name uses an unsupported hash algorithm.');
        }

        $expectedNameHash = hash('sha256', $pubAreaBytes, true);

        if (!hash_equals($expectedNameHash, $certInfo->attestedNameHash)) {
            throw new AttestationVerificationException('TPMS_ATTEST name does not match the hash of pubArea.');
        }

        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($x5c[0]), 64, "\n") . "-----END CERTIFICATE-----\n";
        $publicKey = openssl_pkey_get_public($pem);

        if ($publicKey === false) {
            throw new AttestationVerificationException('Could not read the TPM AIK certificate\'s public key.');
        }

        $digestAlgorithm = match ($alg) {
            -7, -257 => OPENSSL_ALGO_SHA256,
            default => throw new AttestationVerificationException("Unsupported COSE algorithm for tpm attestation: {$alg}"),
        };

        $result = openssl_verify($certInfoBytes, $sig, $publicKey, $digestAlgorithm);

        if ($result !== 1) {
            throw new AttestationVerificationException('"tpm" attestation signature verification failed.');
        }

        return new AttestationResult(trusted: true, attestationType: 'attca');
    }

    private function assertPubAreaMatchesCredential(TpmtPublicKey $pubArea, CoseKey $credentialKey): void
    {
        if ($pubArea->keyType === 'rsa') {
            $modulus = $credentialKey->parameters[-1] ?? null;
            $exponentBytes = $credentialKey->parameters[-2] ?? null;

            if (!is_string($modulus) || !is_string($exponentBytes) || $pubArea->modulus === null || $pubArea->exponent === null
                || !hash_equals($modulus, $pubArea->modulus)
            ) {
                throw new AttestationVerificationException('TPMT_PUBLIC RSA modulus does not match the credential public key.');
            }

            $credentialExponent = 0;

            foreach (str_split($exponentBytes) as $byte) {
                $credentialExponent = ($credentialExponent << 8) | ord($byte);
            }

            // A TPMT_PUBLIC exponent of 0 means the TPM-implied default, 65537.
            $pubAreaExponent = $pubArea->exponent === 0 ? 65537 : $pubArea->exponent;

            if ($credentialExponent !== $pubAreaExponent) {
                throw new AttestationVerificationException('TPMT_PUBLIC RSA exponent does not match the credential public key.');
            }

            return;
        }

        $x = $credentialKey->parameters[-2] ?? null;
        $y = $credentialKey->parameters[-3] ?? null;

        if (!is_string($x) || !is_string($y) || $pubArea->x === null || $pubArea->y === null
            || !hash_equals($x, $pubArea->x) || !hash_equals($y, $pubArea->y)
        ) {
            throw new AttestationVerificationException('TPMT_PUBLIC EC coordinates do not match the credential public key.');
        }
    }
}
