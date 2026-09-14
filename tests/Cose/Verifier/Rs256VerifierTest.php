<?php

declare(strict_types=1);

namespace Tests\Cose\Verifier;

use EzPhp\WebAuthn\Cose\CoseKey;
use EzPhp\WebAuthn\Cose\Verifier\Rs256Verifier;
use Tests\TestCase;

/**
 * Class Rs256VerifierTest
 *
 * @package Tests\Cose\Verifier
 */
final class Rs256VerifierTest extends TestCase
{
    public function test_verifies_a_valid_rs256_signature(): void
    {
        $keyPair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($keyPair);

        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{rsa: array{n: string, e: string}} $details */
        $modulus = $details['rsa']['n'];
        $exponent = $details['rsa']['e'];

        $data = 'signed payload';
        openssl_sign($data, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $coseKey = new CoseKey(algorithm: -257, parameters: [1 => 3, -1 => $modulus, -2 => $exponent]);
        $verifier = new Rs256Verifier();

        self::assertTrue($verifier->verify($coseKey, $data, $signature));
    }

    public function test_rejects_an_invalid_signature(): void
    {
        $keyPair = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($keyPair);

        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{rsa: array{n: string, e: string}} $details */
        $modulus = $details['rsa']['n'];
        $exponent = $details['rsa']['e'];

        $coseKey = new CoseKey(algorithm: -257, parameters: [1 => 3, -1 => $modulus, -2 => $exponent]);
        $verifier = new Rs256Verifier();

        self::assertFalse($verifier->verify($coseKey, 'signed payload', 'not-a-real-signature'));
    }
}
