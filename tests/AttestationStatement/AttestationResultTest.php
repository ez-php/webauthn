<?php

declare(strict_types=1);

namespace Tests\AttestationStatement;

use EzPhp\WebAuthn\AttestationStatement\AttestationResult;
use Tests\TestCase;

/**
 * @package Tests\AttestationStatement
 */
final class AttestationResultTest extends TestCase
{
    public function testExposesTrustAndType(): void
    {
        $result = new AttestationResult(true, 'basic');

        self::assertTrue($result->trusted);
        self::assertSame('basic', $result->attestationType);
    }

    public function testAttestationTypeMayBeNull(): void
    {
        self::assertNull((new AttestationResult(false, null))->attestationType);
    }
}
