<?php

declare(strict_types=1);

namespace Tests\Cose\Verifier;

use EzPhp\WebAuthn\Cose\CoseKey;
use EzPhp\WebAuthn\Cose\Verifier\EdDsaVerifier;
use Tests\TestCase;

/**
 * Class EdDsaVerifierTest
 *
 * @package Tests\Cose\Verifier
 */
final class EdDsaVerifierTest extends TestCase
{
    public function test_verifies_a_valid_ed25519_signature(): void
    {
        $keyPair = sodium_crypto_sign_keypair();
        $publicKey = sodium_crypto_sign_publickey($keyPair);
        $secretKey = sodium_crypto_sign_secretkey($keyPair);

        $data = 'signed payload';
        $signature = sodium_crypto_sign_detached($data, $secretKey);

        $coseKey = new CoseKey(algorithm: -8, parameters: [1 => 1, -1 => 6, -2 => $publicKey]);
        $verifier = new EdDsaVerifier();

        self::assertTrue($verifier->verify($coseKey, $data, $signature));
    }

    public function test_rejects_a_signature_from_a_different_key(): void
    {
        $keyPair = sodium_crypto_sign_keypair();
        $publicKey = sodium_crypto_sign_publickey($keyPair);

        $otherKeyPair = sodium_crypto_sign_keypair();
        $otherSecretKey = sodium_crypto_sign_secretkey($otherKeyPair);
        $signature = sodium_crypto_sign_detached('signed payload', $otherSecretKey);

        $coseKey = new CoseKey(algorithm: -8, parameters: [1 => 1, -1 => 6, -2 => $publicKey]);
        $verifier = new EdDsaVerifier();

        self::assertFalse($verifier->verify($coseKey, 'signed payload', $signature));
    }
}
