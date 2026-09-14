<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn;

/**
 * Relying party configuration for a WebAuthn ceremony: the RP ID (typically
 * the effective domain, e.g. "example.com"), display name, and the set of
 * origins a clientDataJSON is allowed to claim.
 *
 * @package EzPhp\WebAuthn
 */
final readonly class RelyingParty
{
    /**
     * @param list<string> $allowedOrigins
     */
    public function __construct(
        public string $id,
        public string $name,
        public array $allowedOrigins,
    ) {
    }
}
