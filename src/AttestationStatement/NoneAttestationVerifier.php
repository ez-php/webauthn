<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

use EzPhp\WebAuthn\Exception\AttestationVerificationException;

/**
 * Verifies the "none" attestation format (WebAuthn spec §8.7): the
 * authenticator makes no attestation claim at all, so the only thing to
 * check is that attStmt is indeed empty.
 *
 * @package EzPhp\WebAuthn\AttestationStatement
 */
final class NoneAttestationVerifier implements AttestationStatementVerifierInterface
{
    /**
     * {@inheritDoc}
     */
    public function verify(AttestationStatement $statement, string $authenticatorData, string $clientDataHash): AttestationResult
    {
        if ($statement->attStmt !== []) {
            throw new AttestationVerificationException('"none" attestation statement must have an empty attStmt.');
        }

        return new AttestationResult(trusted: false, attestationType: 'none');
    }
}
