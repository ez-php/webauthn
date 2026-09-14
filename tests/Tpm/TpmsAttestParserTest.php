<?php

declare(strict_types=1);

namespace Tests\Tpm;

use EzPhp\WebAuthn\Tpm\TpmsAttestParser;
use Tests\TestCase;

/**
 * Class TpmsAttestParserTest
 *
 * @package Tests\Tpm
 */
final class TpmsAttestParserTest extends TestCase
{
    /**
     * Builds a minimal, structurally valid TPMS_ATTEST (type TPM_ST_ATTEST_CERTIFY).
     */
    private function buildCertInfo(int $magic, int $type, string $extraData, string $nameAlgId, string $nameHash): string
    {
        $qualifiedSigner = '';
        $clockInfo = str_repeat("\x00", 17); // clock(8) + resetCount(4) + restartCount(4) + safe(1)
        $firmwareVersion = str_repeat("\x00", 8);
        $name = $nameAlgId . $nameHash;
        $qualifiedName = '';

        return pack('N', $magic)
            . pack('n', $type)
            . pack('n', strlen($qualifiedSigner)) . $qualifiedSigner
            . pack('n', strlen($extraData)) . $extraData
            . $clockInfo
            . $firmwareVersion
            . pack('n', strlen($name)) . $name
            . pack('n', strlen($qualifiedName)) . $qualifiedName;
    }

    public function test_parses_a_well_formed_cert_info(): void
    {
        $extraData = str_repeat("\xaa", 32);
        $nameHash = str_repeat("\xbb", 32);

        $bytes = $this->buildCertInfo(0xff544347, 0x8017, $extraData, "\x00\x0b", $nameHash);

        $attest = TpmsAttestParser::parse($bytes);

        self::assertSame(0xff544347, $attest->magic);
        self::assertSame(0x8017, $attest->type);
        self::assertSame($extraData, $attest->extraData);
        self::assertSame("\x00\x0b", $attest->attestedNameAlgId);
        self::assertSame($nameHash, $attest->attestedNameHash);
    }

    public function test_rejects_truncated_input(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        TpmsAttestParser::parse("\x00\x01");
    }
}
