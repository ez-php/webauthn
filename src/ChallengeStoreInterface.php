<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn;

/**
 * Application-implemented single-use challenge storage. This module never
 * persists state itself.
 *
 * @package EzPhp\WebAuthn
 */
interface ChallengeStoreInterface
{
    public function generate(): Challenge;

    /**
     * Return the challenge for $challengeId and mark it consumed (single
     * use), or null if it doesn't exist / was already consumed.
     */
    public function consume(string $challengeId): ?Challenge;
}
