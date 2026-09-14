<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn;

use EzPhp\WebAuthn\Exception\InvalidClientDataException;

/**
 * Verifies a clientDataJSON payload's type, challenge, and origin against
 * the ceremony's expectations. Shared by RegistrationCeremony (expects
 * "webauthn.create") and AssertionCeremony (expects "webauthn.get").
 *
 * @package EzPhp\WebAuthn
 */
final class ClientDataValidator
{
    /**
     * @throws InvalidClientDataException
     */
    public static function validate(
        string $clientDataJson,
        string $expectedType,
        Challenge $challenge,
        RelyingParty $relyingParty,
        \DateTimeImmutable $now,
    ): void {
        if ($challenge->isExpired($now)) {
            throw new InvalidClientDataException('Challenge has expired.');
        }

        try {
            /** @var mixed $clientData */
            $clientData = json_decode($clientDataJson, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new InvalidClientDataException('clientDataJSON is not valid JSON.', previous: $exception);
        }

        if (!is_array($clientData)) {
            throw new InvalidClientDataException('clientDataJSON must decode to an object.');
        }

        $type = $clientData['type'] ?? null;

        if ($type !== $expectedType) {
            throw new InvalidClientDataException("clientDataJSON type mismatch: expected \"{$expectedType}\".");
        }

        $challengeClaim = $clientData['challenge'] ?? null;

        if (!is_string($challengeClaim)) {
            throw new InvalidClientDataException('clientDataJSON is missing the challenge.');
        }

        $decodedChallenge = base64_decode(strtr($challengeClaim, '-_', '+/'), strict: true);

        if ($decodedChallenge === false || !hash_equals($challenge->value, $decodedChallenge)) {
            throw new InvalidClientDataException('clientDataJSON challenge does not match the expected value.');
        }

        $origin = $clientData['origin'] ?? null;

        if (!is_string($origin) || !in_array($origin, $relyingParty->allowedOrigins, strict: true)) {
            throw new InvalidClientDataException('clientDataJSON origin is not an allowed origin for this relying party.');
        }
    }
}
