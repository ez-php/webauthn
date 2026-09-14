<?php

declare(strict_types=1);

namespace Tests\Tpm;

use EzPhp\WebAuthn\Tpm\TpmtPublicParser;
use Tests\TestCase;

/**
 * Class TpmtPublicParserTest
 *
 * @package Tests\Tpm
 */
final class TpmtPublicParserTest extends TestCase
{
    private function packUint16(int $value): string
    {
        return pack('n', $value);
    }

    private function packUint32(int $value): string
    {
        return pack('N', $value);
    }

    public function test_parses_an_rsa_public_area(): void
    {
        $modulus = str_repeat("\xab", 256);

        $bytes = $this->packUint16(0x0001)  // type: TPM_ALG_RSA
            . $this->packUint16(0x000b)     // nameAlg: TPM_ALG_SHA256 (irrelevant to this parser)
            . $this->packUint32(0)          // objectAttributes
            . $this->packUint16(0)          // authPolicy size: 0
            . $this->packUint16(0x0010)     // symmetric: TPM_ALG_NULL
            . $this->packUint16(0x0010)     // scheme: TPM_ALG_NULL
            . $this->packUint16(2048)       // keyBits
            . $this->packUint32(0)          // exponent: 0 (means default 65537)
            . $this->packUint16(strlen($modulus)) . $modulus; // unique (modulus)

        $key = TpmtPublicParser::parse($bytes);

        self::assertSame('rsa', $key->keyType);
        self::assertSame($modulus, $key->modulus);
        self::assertSame(0, $key->exponent);
    }

    public function test_parses_an_ecc_public_area(): void
    {
        $x = str_repeat("\x01", 32);
        $y = str_repeat("\x02", 32);

        $bytes = $this->packUint16(0x0023)  // type: TPM_ALG_ECC
            . $this->packUint16(0x000b)     // nameAlg
            . $this->packUint32(0)          // objectAttributes
            . $this->packUint16(0)          // authPolicy size: 0
            . $this->packUint16(0x0010)     // symmetric: TPM_ALG_NULL
            . $this->packUint16(0x0010)     // scheme: TPM_ALG_NULL
            . $this->packUint16(0x0003)     // curveID: TPM_ECC_NIST_P256
            . $this->packUint16(0x0010)     // kdf: TPM_ALG_NULL
            . $this->packUint16(strlen($x)) . $x
            . $this->packUint16(strlen($y)) . $y;

        $key = TpmtPublicParser::parse($bytes);

        self::assertSame('ecc', $key->keyType);
        self::assertSame($x, $key->x);
        self::assertSame($y, $key->y);
    }

    public function test_rejects_an_unsupported_key_type(): void
    {
        $bytes = $this->packUint16(0x0025); // TPM_ALG_KEYEDHASH — unsupported

        $this->expectException(\InvalidArgumentException::class);

        TpmtPublicParser::parse($bytes);
    }

    public function test_rejects_truncated_input(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        TpmtPublicParser::parse("\x00\x01");
    }
}
