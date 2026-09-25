<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

/**
 * The outcome of verifying one attestation statement.
 *
 * @package EzPhp\WebAuthn\AttestationStatement
 */
final readonly class AttestationResult
{
    /**
     * AttestationResult Constructor
     *
     * @param bool        $trusted
     * @param string|null $attestationType
     */
    public function __construct(
        public bool $trusted,
        public ?string $attestationType,
    ) {
    }
}
