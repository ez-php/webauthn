<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\AttestationStatement;

use EzPhp\WebAuthn\Exception\AttestationVerificationException;

/**
 * Verifies one attestation statement format.
 *
 * @package EzPhp\WebAuthn\AttestationStatement
 */
interface AttestationStatementVerifierInterface
{
    /**
     * @throws AttestationVerificationException
     */
    public function verify(AttestationStatement $statement, string $authenticatorData, string $clientDataHash): AttestationResult;
}
