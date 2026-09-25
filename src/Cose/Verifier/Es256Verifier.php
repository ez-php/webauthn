<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Cose\Verifier;

use EzPhp\WebAuthn\Cose\CoseKey;
use EzPhp\WebAuthn\Cose\SignatureVerifierInterface;

/**
 * Verifies COSE algorithm -7 (ECDSA using P-256 and SHA-256) signatures.
 *
 * @package EzPhp\WebAuthn\Cose\Verifier
 */
final class Es256Verifier implements SignatureVerifierInterface
{
    /**
     * {@inheritDoc}
     */
    public function verify(CoseKey $key, string $signedData, string $signature): bool
    {
        $publicKey = openssl_pkey_get_public($key->toPem());

        if ($publicKey === false) {
            return false;
        }

        $result = openssl_verify($signedData, $signature, $publicKey, OPENSSL_ALGO_SHA256);

        return $result === 1;
    }
}
