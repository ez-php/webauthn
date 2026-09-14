<?php

declare(strict_types=1);

namespace Tests\Cose;

use EzPhp\WebAuthn\Cose\CoseKey;
use Tests\TestCase;

/**
 * Class CoseKeyTest
 *
 * @package Tests\Cose
 */
final class CoseKeyTest extends TestCase
{
    public function test_parses_es256_key_algorithm_and_parameters(): void
    {
        // COSE_Key map: {1: 2 (kty=EC2), 3: -7 (alg=ES256), -1: 1 (crv=P-256), -2: h'01', -3: h'02'}
        $cbor = "\xa5\x01\x02\x03\x26\x20\x01\x21\x41\x01\x22\x41\x02";

        $key = CoseKey::fromCbor($cbor);

        self::assertSame(-7, $key->algorithm);
        self::assertSame(2, $key->parameters[1]);
        self::assertSame("\x01", $key->parameters[-2]);
        self::assertSame("\x02", $key->parameters[-3]);
    }

    public function test_throws_when_algorithm_label_is_missing(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // COSE_Key map with only {1: 2} — no alg (label 3)
        CoseKey::fromCbor("\xa1\x01\x02");
    }

    public function test_ec_to_pem_rejects_a_non_p256_curve(): void
    {
        $key = new CoseKey(algorithm: -7, parameters: [
            1 => 2,
            -1 => 2, // crv=2 (P-384), not the supported P-256
            -2 => str_repeat("\x01", 32),
            -3 => str_repeat("\x02", 32),
        ]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Only P-256 (crv=1) EC keys are supported.');

        $key->toPem();
    }

    public function test_rsa_to_pem_rejects_an_oversized_modulus(): void
    {
        $key = new CoseKey(algorithm: -257, parameters: [
            1 => 3,
            -1 => str_repeat("\x01", 2000), // far beyond the 1024-byte bound
            -2 => "\x01\x00\x01",
        ]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('RSA COSE key modulus size is out of the supported range (128-1024 bytes).');

        $key->toPem();
    }

    public function test_rsa_to_pem_rejects_an_undersized_modulus(): void
    {
        $key = new CoseKey(algorithm: -257, parameters: [
            1 => 3,
            -1 => str_repeat("\x01", 64), // below the 128-byte bound
            -2 => "\x01\x00\x01",
        ]);

        $this->expectException(\InvalidArgumentException::class);

        $key->toPem();
    }

    public function test_rsa_to_pem_rejects_an_oversized_exponent(): void
    {
        $key = new CoseKey(algorithm: -257, parameters: [
            1 => 3,
            -1 => str_repeat("\x01", 256),
            -2 => str_repeat("\x01", 9), // exceeds the 8-byte bound
        ]);

        $this->expectException(\InvalidArgumentException::class);

        $key->toPem();
    }
}
