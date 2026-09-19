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

    /**
     * @param int    $symmetric
     * @param int    $scheme
     * @param string $modulus
     */
    private function rsaArea(int $symmetric = 0x0010, int $scheme = 0x0010, string $modulus = ''): string
    {
        $modulus = $modulus === '' ? str_repeat("\xab", 256) : $modulus;

        return $this->packUint16(0x0001) . $this->packUint16(0x000b) . $this->packUint32(0) . $this->packUint16(0)
            . $this->packUint16($symmetric)
            . $this->packUint16($scheme)
            . $this->packUint16(2048)
            . $this->packUint32(0)
            . $this->packUint16(strlen($modulus)) . $modulus;
    }

    private function eccArea(
        int $symmetric = 0x0010,
        int $scheme = 0x0010,
        int $curve = 0x0003,
        int $kdf = 0x0010,
        int $xLength = 32,
        int $yLength = 32,
    ): string {
        return $this->packUint16(0x0023) . $this->packUint16(0x000b) . $this->packUint32(0) . $this->packUint16(0)
            . $this->packUint16($symmetric)
            . $this->packUint16($scheme)
            . $this->packUint16($curve)
            . $this->packUint16($kdf)
            . $this->packUint16($xLength) . str_repeat("\x01", $xLength)
            . $this->packUint16($yLength) . str_repeat("\x02", $yLength);
    }

    /**
     * @param string $bytes
     */
    private function assertRejected(string $bytes, string $messagePart = ''): void
    {
        try {
            TpmtPublicParser::parse($bytes);
        } catch (\InvalidArgumentException $e) {
            if ($messagePart !== '') {
                self::assertStringContainsString($messagePart, $e->getMessage());
            }

            $this->addToAssertionCount(1);

            return;
        }

        self::fail('Expected the parser to reject the input.');
    }

    public function test_rejects_a_non_null_symmetric_algorithm_for_rsa(): void
    {
        $this->assertRejected($this->rsaArea(symmetric: 0x0006), 'symmetric');
    }

    public function test_rejects_a_non_null_scheme_for_rsa(): void
    {
        $this->assertRejected($this->rsaArea(scheme: 0x0014), 'scheme');
    }

    public function test_rejects_a_non_null_symmetric_algorithm_for_ecc(): void
    {
        $this->assertRejected($this->eccArea(symmetric: 0x0006), 'symmetric');
    }

    public function test_rejects_a_non_null_scheme_for_ecc(): void
    {
        $this->assertRejected($this->eccArea(scheme: 0x0018), 'scheme');
    }

    public function test_rejects_an_unsupported_ecc_curve(): void
    {
        // 0x0004 = TPM_ECC_NIST_P384
        $this->assertRejected($this->eccArea(curve: 0x0004), 'curve');
    }

    public function test_rejects_a_non_null_key_derivation_function(): void
    {
        $this->assertRejected($this->eccArea(kdf: 0x0020), 'kdf');
    }

    public function test_rejects_ecc_coordinates_that_are_not_32_bytes(): void
    {
        $this->assertRejected($this->eccArea(xLength: 31), '32 bytes');
        $this->assertRejected($this->eccArea(yLength: 33), '32 bytes');
    }

    public function test_rejects_a_declared_auth_policy_larger_than_the_input(): void
    {
        $bytes = $this->packUint16(0x0001) . $this->packUint16(0x000b) . $this->packUint32(0)
            . $this->packUint16(0xffff) . 'short';

        $this->assertRejected($bytes, 'Unexpected end');
    }

    public function test_rejects_a_declared_modulus_larger_than_the_input(): void
    {
        $bytes = substr($this->rsaArea(), 0, -1);

        $this->assertRejected($bytes, 'Unexpected end');
    }

    public function test_every_truncation_of_a_valid_area_is_rejected_without_warnings(): void
    {
        foreach ([$this->rsaArea(), $this->eccArea()] as $valid) {
            for ($length = 0; $length < strlen($valid); $length++) {
                $this->assertRejected(substr($valid, 0, $length));
            }

            // The full input still parses, so the loop above really covered every shorter prefix.
            self::assertContains(TpmtPublicParser::parse($valid)->keyType, ['rsa', 'ecc']);
        }
    }

    public function test_rejects_empty_input(): void
    {
        $this->assertRejected('');
    }
}
