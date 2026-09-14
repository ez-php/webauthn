<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

/**
 * A decoded attestation statement: its format identifier and the raw
 * format-specific CBOR map (attStmt).
 *
 * @package EzPhp\WebAuthn\AttestationStatement
 */
final readonly class AttestationStatement
{
    /**
     * @param array<string, mixed> $attStmt
     */
    public function __construct(
        public string $fmt,
        public array $attStmt,
    ) {
    }
}
