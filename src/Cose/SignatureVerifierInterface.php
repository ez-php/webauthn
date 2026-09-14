<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Cose;

/**
 * Verifies a signature against a COSE public key for one specific COSE
 * algorithm. One implementation per algorithm, dispatched by
 * CoseKey::$algorithm.
 *
 * @package EzPhp\WebAuthn\Cose
 */
interface SignatureVerifierInterface
{
    public function verify(CoseKey $key, string $signedData, string $signature): bool;
}
