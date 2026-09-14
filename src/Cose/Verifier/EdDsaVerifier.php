<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Cose\Verifier;

use EzPhp\WebAuthn\Cose\CoseKey;
use EzPhp\WebAuthn\Cose\SignatureVerifierInterface;

/**
 * Verifies COSE algorithm -8 (EdDSA, in practice Ed25519) signatures using
 * the raw OKP public key bytes rather than a PEM encoding.
 *
 * @package EzPhp\WebAuthn\Cose\Verifier
 */
final class EdDsaVerifier implements SignatureVerifierInterface
{
    public function verify(CoseKey $key, string $signedData, string $signature): bool
    {
        $publicKey = $key->parameters[-2] ?? null;

        if (!is_string($publicKey) || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false;
        }

        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }

        try {
            return sodium_crypto_sign_verify_detached($signature, $signedData, $publicKey);
        } catch (\SodiumException) {
            return false;
        }
    }
}
