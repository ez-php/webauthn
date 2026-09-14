<?php

declare(strict_types=1);

namespace Tests\AttestationStatement;

use EzPhp\WebAuthn\AttestationStatement\AttestationStatement;
use EzPhp\WebAuthn\AttestationStatement\AttestationStatementVerifierRegistry;
use EzPhp\WebAuthn\AttestationStatement\NoneAttestationVerifier;
use EzPhp\WebAuthn\Exception\UnknownAttestationFormatException;
use Tests\TestCase;

/**
 * Class AttestationStatementVerifierRegistryTest
 *
 * @package Tests\AttestationStatement
 */
final class AttestationStatementVerifierRegistryTest extends TestCase
{
    public function test_dispatches_to_the_registered_verifier(): void
    {
        $registry = new AttestationStatementVerifierRegistry(['none' => new NoneAttestationVerifier()]);
        $result = $registry->verify(new AttestationStatement(fmt: 'none', attStmt: []), 'auth-data', 'client-data-hash');

        self::assertSame('none', $result->attestationType);
    }

    public function test_throws_for_an_unregistered_format(): void
    {
        $registry = new AttestationStatementVerifierRegistry([]);

        $this->expectException(UnknownAttestationFormatException::class);

        $registry->verify(new AttestationStatement(fmt: 'packed', attStmt: []), 'auth-data', 'client-data-hash');
    }
}
