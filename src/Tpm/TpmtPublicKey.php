<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Tpm;

/**
 * The key material extracted from a parsed TPMT_PUBLIC structure.
 *
 * @package EzPhp\WebAuthn\Tpm
 */
final readonly class TpmtPublicKey
{
    public function __construct(
        public string $keyType,
        public ?string $modulus,
        public ?int $exponent,
        public ?string $x,
        public ?string $y,
    ) {
    }
}
