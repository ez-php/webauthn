<?php

declare(strict_types=1);

namespace Tests\AttestationStatement;

use EzPhp\WebAuthn\AttestationStatement\AttestationStatement;
use EzPhp\WebAuthn\AttestationStatement\NoneAttestationVerifier;
use EzPhp\WebAuthn\Exception\AttestationVerificationException;
use Tests\TestCase;

/**
 * Class NoneAttestationVerifierTest
 *
 * @package Tests\AttestationStatement
 */
final class NoneAttestationVerifierTest extends TestCase
{
    public function test_accepts_an_empty_attestation_statement(): void
    {
        $verifier = new NoneAttestationVerifier();
        $result = $verifier->verify(new AttestationStatement(fmt: 'none', attStmt: []), 'auth-data', 'client-data-hash');

        self::assertFalse($result->trusted);
        self::assertSame('none', $result->attestationType);
    }

    public function test_rejects_a_non_empty_attestation_statement(): void
    {
        $verifier = new NoneAttestationVerifier();

        $this->expectException(AttestationVerificationException::class);

        $verifier->verify(new AttestationStatement(fmt: 'none', attStmt: ['sig' => 'unexpected']), 'auth-data', 'client-data-hash');
    }
}
