<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Tpm;

/**
 * Parses a TPM 2.0 TPMT_PUBLIC structure (the `pubArea` field of a `tpm`
 * attestation statement). Scoped to TPM_ALG_RSA and TPM_ALG_ECC key types
 * with TPM_ALG_NULL symmetric/scheme sub-fields — the shape every mainstream
 * TPM attestation key uses. Not a general TPM structure parser.
 *
 * @package EzPhp\WebAuthn\Tpm
 */
final class TpmtPublicParser
{
    private const int TPM_ALG_RSA = 0x0001;
    private const int TPM_ALG_NULL = 0x0010;
    private const int TPM_ALG_ECC = 0x0023;
    private const int TPM_ECC_NIST_P256 = 0x0003;

    public static function parse(string $bytes): TpmtPublicKey
    {
        $offset = 0;

        $type = self::readUint16($bytes, $offset);
        self::readUint16($bytes, $offset); // nameAlg — not needed by this parser
        self::readUint32($bytes, $offset); // objectAttributes — not needed

        $authPolicySize = self::readUint16($bytes, $offset);
        self::readBytes($bytes, $offset, $authPolicySize); // authPolicy — skipped

        return match ($type) {
            self::TPM_ALG_RSA => self::parseRsaParameters($bytes, $offset),
            self::TPM_ALG_ECC => self::parseEccParameters($bytes, $offset),
            default => throw new \InvalidArgumentException("Unsupported TPMT_PUBLIC key type: {$type}"),
        };
    }

    private static function parseRsaParameters(string $bytes, int &$offset): TpmtPublicKey
    {
        self::expectNullAlgorithm($bytes, $offset, 'symmetric');
        self::expectNullAlgorithm($bytes, $offset, 'scheme');

        self::readUint16($bytes, $offset); // keyBits — not needed once we have the modulus length
        $exponent = self::readUint32($bytes, $offset);

        $modulusSize = self::readUint16($bytes, $offset);
        $modulus = self::readBytes($bytes, $offset, $modulusSize);

        return new TpmtPublicKey(keyType: 'rsa', modulus: $modulus, exponent: $exponent, x: null, y: null);
    }

    private static function parseEccParameters(string $bytes, int &$offset): TpmtPublicKey
    {
        self::expectNullAlgorithm($bytes, $offset, 'symmetric');
        self::expectNullAlgorithm($bytes, $offset, 'scheme');

        $curveId = self::readUint16($bytes, $offset);

        if ($curveId !== self::TPM_ECC_NIST_P256) {
            throw new \InvalidArgumentException("Unsupported TPMT_PUBLIC ECC curve: {$curveId}");
        }

        self::expectNullAlgorithm($bytes, $offset, 'kdf');

        $xSize = self::readUint16($bytes, $offset);
        $x = self::readBytes($bytes, $offset, $xSize);
        $ySize = self::readUint16($bytes, $offset);
        $y = self::readBytes($bytes, $offset, $ySize);

        if (strlen($x) !== 32 || strlen($y) !== 32) {
            throw new \InvalidArgumentException('TPMT_PUBLIC ECC coordinates must be exactly 32 bytes for P-256.');
        }

        return new TpmtPublicKey(keyType: 'ecc', modulus: null, exponent: null, x: $x, y: $y);
    }

    private static function expectNullAlgorithm(string $bytes, int &$offset, string $fieldName): void
    {
        $algorithm = self::readUint16($bytes, $offset);

        if ($algorithm !== self::TPM_ALG_NULL) {
            throw new \InvalidArgumentException("Unsupported non-NULL TPMT_PUBLIC {$fieldName} algorithm: {$algorithm}");
        }
    }

    private static function readUint16(string $bytes, int &$offset): int
    {
        $value = unpack('n', self::readBytes($bytes, $offset, 2));

        if ($value === false) {
            throw new \InvalidArgumentException('Failed to read a UINT16 from TPMT_PUBLIC.');
        }

        return $value[1];
    }

    private static function readUint32(string $bytes, int &$offset): int
    {
        $value = unpack('N', self::readBytes($bytes, $offset, 4));

        if ($value === false) {
            throw new \InvalidArgumentException('Failed to read a UINT32 from TPMT_PUBLIC.');
        }

        return $value[1];
    }

    private static function readBytes(string $bytes, int &$offset, int $length): string
    {
        $value = substr($bytes, $offset, $length);

        if (strlen($value) !== $length) {
            throw new \InvalidArgumentException('Unexpected end of TPMT_PUBLIC input.');
        }

        $offset += $length;

        return $value;
    }
}
