<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

use EzPhp\WebAuthn\Exception\UnknownAttestationFormatException;

/**
 * Dispatches attestation statement verification to the registered verifier
 * for the statement's `fmt` value.
 *
 * @package EzPhp\WebAuthn\AttestationStatement
 */
final class AttestationStatementVerifierRegistry
{
    /**
     * @param array<string, AttestationStatementVerifierInterface> $verifiersByFormat
     */
    public function __construct(
        private readonly array $verifiersByFormat,
    ) {
    }

    public function verify(AttestationStatement $statement, string $authenticatorData, string $clientDataHash): AttestationResult
    {
        $verifier = $this->verifiersByFormat[$statement->fmt] ?? null;

        if ($verifier === null) {
            throw new UnknownAttestationFormatException("No verifier registered for attestation format \"{$statement->fmt}\".");
        }

        return $verifier->verify($statement, $authenticatorData, $clientDataHash);
    }
}
