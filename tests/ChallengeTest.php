<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebAuthn\Challenge;

/**
 * Class ChallengeTest
 *
 * @package Tests
 */
final class ChallengeTest extends TestCase
{
    public function test_rejects_a_challenge_value_shorter_than_16_bytes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Challenge value must be at least 16 bytes.');

        new Challenge(id: 'chal-1', value: str_repeat('a', 15), expiresAt: new \DateTimeImmutable('+5 minutes'));
    }

    public function test_accepts_a_challenge_value_of_exactly_16_bytes(): void
    {
        $challenge = new Challenge(id: 'chal-1', value: str_repeat('a', 16), expiresAt: new \DateTimeImmutable('+5 minutes'));

        self::assertSame(16, strlen($challenge->value));
    }
}
