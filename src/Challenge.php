<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn;

/**
 * A single-use registration/assertion challenge. The application persists
 * and retrieves these via ChallengeStoreInterface; this module never stores
 * state itself.
 *
 * @package EzPhp\WebAuthn
 */
final readonly class Challenge
{
    /**
     * Challenge Constructor
     *
     * @param string             $id
     * @param string             $value
     * @param \DateTimeImmutable $expiresAt
     */
    public function __construct(
        public string $id,
        public string $value,
        public \DateTimeImmutable $expiresAt,
    ) {
        if (strlen($this->value) < 16) {
            throw new \InvalidArgumentException('Challenge value must be at least 16 bytes.');
        }
    }

    /**
     * Whether the challenge has expired at the given time.
     */
    public function isExpired(\DateTimeImmutable $now): bool
    {
        return $now > $this->expiresAt;
    }
}
