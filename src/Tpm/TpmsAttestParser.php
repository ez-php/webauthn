<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Tpm;

/**
 * Parses a TPM 2.0 TPMS_ATTEST structure (the `certInfo` field of a `tpm`
 * attestation statement), assuming TPM_ST_ATTEST_CERTIFY's `attested` union
 * arm (TPMS_CERTIFY_INFO: a `name` field followed by a `qualifiedName`
 * field, both TPM2B_NAME). Does not itself validate `magic`/`type` — see
 * TpmAttestationVerifier, which owns that check so it can report which
 * expectation failed.
 *
 * @package EzPhp\WebAuthn\Tpm
 */
final class TpmsAttestParser
{
    public static function parse(string $bytes): TpmsAttest
    {
        $offset = 0;

        $magic = self::readUint32($bytes, $offset);
        $type = self::readUint16($bytes, $offset);

        $qualifiedSignerSize = self::readUint16($bytes, $offset);
        self::readBytes($bytes, $offset, $qualifiedSignerSize); // qualifiedSigner — skipped

        $extraDataSize = self::readUint16($bytes, $offset);
        $extraData = self::readBytes($bytes, $offset, $extraDataSize);

        self::readBytes($bytes, $offset, 17); // clockInfo (fixed 17 bytes) — skipped
        self::readBytes($bytes, $offset, 8);  // firmwareVersion (UINT64) — skipped

        $nameSize = self::readUint16($bytes, $offset);
        $name = self::readBytes($bytes, $offset, $nameSize);

        if (strlen($name) < 2) {
            throw new \InvalidArgumentException('TPMS_ATTEST name field is too short to contain a hash algorithm ID.');
        }

        $nameAlgId = substr($name, 0, 2);
        $nameHash = substr($name, 2);

        $qualifiedNameSize = self::readUint16($bytes, $offset);
        self::readBytes($bytes, $offset, $qualifiedNameSize); // qualifiedName — skipped

        return new TpmsAttest(
            magic: $magic,
            type: $type,
            extraData: $extraData,
            attestedNameAlgId: $nameAlgId,
            attestedNameHash: $nameHash,
        );
    }

    private static function readUint16(string $bytes, int &$offset): int
    {
        $value = unpack('n', self::readBytes($bytes, $offset, 2));

        if ($value === false) {
            throw new \InvalidArgumentException('Failed to read a UINT16 from TPMS_ATTEST.');
        }

        return $value[1];
    }

    private static function readUint32(string $bytes, int &$offset): int
    {
        $value = unpack('N', self::readBytes($bytes, $offset, 4));

        if ($value === false) {
            throw new \InvalidArgumentException('Failed to read a UINT32 from TPMS_ATTEST.');
        }

        return $value[1];
    }

    private static function readBytes(string $bytes, int &$offset, int $length): string
    {
        $value = substr($bytes, $offset, $length);

        if (strlen($value) !== $length) {
            throw new \InvalidArgumentException('Unexpected end of TPMS_ATTEST input.');
        }

        $offset += $length;

        return $value;
    }
}
