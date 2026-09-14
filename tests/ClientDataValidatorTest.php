<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebAuthn\Challenge;
use EzPhp\WebAuthn\ClientDataValidator;
use EzPhp\WebAuthn\Exception\InvalidClientDataException;
use EzPhp\WebAuthn\RelyingParty;

/**
 * Class ClientDataValidatorTest
 *
 * @package Tests
 */
final class ClientDataValidatorTest extends TestCase
{
    private function relyingParty(): RelyingParty
    {
        return new RelyingParty(id: 'example.com', name: 'Example', allowedOrigins: ['https://example.com']);
    }

    private function challenge(): Challenge
    {
        return new Challenge(id: 'chal-1', value: 'raw-challenge-bytes', expiresAt: new \DateTimeImmutable('+5 minutes'));
    }

    public function test_accepts_matching_client_data(): void
    {
        $clientData = json_encode([
            'type' => 'webauthn.create',
            'challenge' => rtrim(strtr(base64_encode('raw-challenge-bytes'), '+/', '-_'), '='),
            'origin' => 'https://example.com',
        ]);
        self::assertIsString($clientData);

        ClientDataValidator::validate($clientData, 'webauthn.create', $this->challenge(), $this->relyingParty(), new \DateTimeImmutable());

        $this->addToAssertionCount(1);
    }

    public function test_rejects_wrong_type(): void
    {
        $clientData = json_encode([
            'type' => 'webauthn.get',
            'challenge' => rtrim(strtr(base64_encode('raw-challenge-bytes'), '+/', '-_'), '='),
            'origin' => 'https://example.com',
        ]);
        self::assertIsString($clientData);

        $this->expectException(InvalidClientDataException::class);

        ClientDataValidator::validate($clientData, 'webauthn.create', $this->challenge(), $this->relyingParty(), new \DateTimeImmutable());
    }

    public function test_rejects_origin_not_in_allow_list(): void
    {
        $clientData = json_encode([
            'type' => 'webauthn.create',
            'challenge' => rtrim(strtr(base64_encode('raw-challenge-bytes'), '+/', '-_'), '='),
            'origin' => 'https://evil.example',
        ]);
        self::assertIsString($clientData);

        $this->expectException(InvalidClientDataException::class);

        ClientDataValidator::validate($clientData, 'webauthn.create', $this->challenge(), $this->relyingParty(), new \DateTimeImmutable());
    }

    public function test_rejects_expired_challenge(): void
    {
        $clientData = json_encode([
            'type' => 'webauthn.create',
            'challenge' => rtrim(strtr(base64_encode('raw-challenge-bytes'), '+/', '-_'), '='),
            'origin' => 'https://example.com',
        ]);
        self::assertIsString($clientData);

        $expired = new Challenge(id: 'chal-1', value: 'raw-challenge-bytes', expiresAt: new \DateTimeImmutable('-1 minute'));

        $this->expectException(InvalidClientDataException::class);

        ClientDataValidator::validate($clientData, 'webauthn.create', $expired, $this->relyingParty(), new \DateTimeImmutable());
    }

    public function test_rejects_malformed_json(): void
    {
        $this->expectException(InvalidClientDataException::class);

        ClientDataValidator::validate('not json', 'webauthn.create', $this->challenge(), $this->relyingParty(), new \DateTimeImmutable());
    }
}
