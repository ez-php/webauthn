<?php

declare(strict_types=1);

namespace Tests\Cose\Verifier;

use EzPhp\WebAuthn\Cose\CoseKey;
use EzPhp\WebAuthn\Cose\Verifier\Es256Verifier;
use Tests\TestCase;

/**
 * Class Es256VerifierTest
 *
 * @package Tests\Cose\Verifier
 */
final class Es256VerifierTest extends TestCase
{
    public function test_verifies_a_valid_es256_signature(): void
    {
        $keyPair = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        self::assertNotFalse($keyPair);

        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $x = $details['ec']['x'];
        $y = $details['ec']['y'];

        $data = 'signed payload';
        openssl_sign($data, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $coseKey = new CoseKey(algorithm: -7, parameters: [1 => 2, -1 => 1, -2 => $x, -3 => $y]);
        $verifier = new Es256Verifier();

        self::assertTrue($verifier->verify($coseKey, $data, $signature));
    }

    public function test_rejects_a_tampered_signature(): void
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);

        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $x = $details['ec']['x'];
        $y = $details['ec']['y'];

        openssl_sign('signed payload', $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $coseKey = new CoseKey(algorithm: -7, parameters: [1 => 2, -1 => 1, -2 => $x, -3 => $y]);
        $verifier = new Es256Verifier();

        self::assertFalse($verifier->verify($coseKey, 'a different payload', $signature));
    }
}
