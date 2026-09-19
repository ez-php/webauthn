<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\Contracts\SecondFactorResult;
use EzPhp\WebAuthn\AssertionCeremony;
use EzPhp\WebAuthn\Challenge;
use EzPhp\WebAuthn\Cose\CoseKey;
use EzPhp\WebAuthn\Cose\Verifier\Es256Verifier;
use EzPhp\WebAuthn\CredentialRepositoryInterface;
use EzPhp\WebAuthn\PublicKeyCredentialSource;
use EzPhp\WebAuthn\RelyingParty;
use EzPhp\WebAuthn\SecondFactorAssertionVerifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;

/**
 * Class SecondFactorAssertionVerifierTest
 *
 * Demonstrates that a WebAuthn assertion, once wrapped by
 * SecondFactorAssertionVerifier, produces the same shared
 * EzPhp\Contracts\SecondFactorResult outcome type that
 * EzPhp\TwoFactor\TwoFactorManager::verifyForUser() returns — the same
 * login-flow abstraction, satisfied by two independent modules.
 *
 * @package Tests
 */
#[CoversClass(SecondFactorAssertionVerifier::class)]
#[UsesClass(AssertionCeremony::class)]
final class SecondFactorAssertionVerifierTest extends TestCase
{
    private function relyingParty(): RelyingParty
    {
        return new RelyingParty(id: 'example.com', name: 'Example', allowedOrigins: ['https://example.com']);
    }

    private function challenge(): Challenge
    {
        return new Challenge(id: 'chal-1', value: 'raw-challenge-bytes', expiresAt: new \DateTimeImmutable('+5 minutes'));
    }

    private function clientDataJson(): string
    {
        $json = json_encode([
            'type' => 'webauthn.get',
            'challenge' => rtrim(strtr(base64_encode('raw-challenge-bytes'), '+/', '-_'), '='),
            'origin' => 'https://example.com',
        ]);
        self::assertIsString($json);

        return $json;
    }

    private function authenticatorData(int $signCount): string
    {
        $rpIdHash = hash('sha256', 'example.com', true);
        $flags = "\x01";

        return $rpIdHash . $flags . pack('N', $signCount);
    }

    private function repositoryWith(PublicKeyCredentialSource $source): CredentialRepositoryInterface
    {
        return new class ($source) implements CredentialRepositoryInterface {
            public function __construct(private readonly PublicKeyCredentialSource $source)
            {
            }

            public function findByCredentialId(string $credentialId): ?PublicKeyCredentialSource
            {
                return $credentialId === $this->source->credentialId ? $this->source : null;
            }

            public function findByUserHandle(string $userHandle): array
            {
                return [$this->source];
            }

            public function save(PublicKeyCredentialSource $source): void
            {
            }
        };
    }

    public function testVerifyReturnsSatisfiedForAValidAssertion(): void
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);
        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $coseKey = new CoseKey(algorithm: -7, parameters: [1 => 2, -1 => 1, -2 => $details['ec']['x'], -3 => $details['ec']['y']]);

        $storedSource = new PublicKeyCredentialSource(
            credentialId: 'cred-1',
            publicKey: $coseKey,
            signCount: 3,
            aaguid: null,
            userHandle: 'user-1',
            transports: [],
        );

        $clientDataJson = $this->clientDataJson();
        $authenticatorData = $this->authenticatorData(signCount: 4);
        $clientDataHash = hash('sha256', $clientDataJson, true);
        openssl_sign($authenticatorData . $clientDataHash, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $ceremony = new AssertionCeremony($this->relyingParty(), [-7 => new Es256Verifier()]);
        $verifier = new SecondFactorAssertionVerifier($ceremony);

        $result = $verifier->verify(
            $this->challenge(),
            $clientDataJson,
            $authenticatorData,
            $signature,
            'cred-1',
            $this->repositoryWith($storedSource),
        );

        self::assertSame(SecondFactorResult::Satisfied, $result);
        $credential = $verifier->getVerifiedCredential();
        self::assertNotNull($credential);
        self::assertSame(4, $credential->signCount);
    }

    public function testVerifyReturnsNotSatisfiedForAnInvalidSignature(): void
    {
        $keyPair = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($keyPair);
        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $coseKey = new CoseKey(algorithm: -7, parameters: [1 => 2, -1 => 1, -2 => $details['ec']['x'], -3 => $details['ec']['y']]);

        $storedSource = new PublicKeyCredentialSource(
            credentialId: 'cred-1',
            publicKey: $coseKey,
            signCount: 0,
            aaguid: null,
            userHandle: 'user-1',
            transports: [],
        );

        $ceremony = new AssertionCeremony($this->relyingParty(), [-7 => new Es256Verifier()]);
        $verifier = new SecondFactorAssertionVerifier($ceremony);

        $result = $verifier->verify(
            $this->challenge(),
            $this->clientDataJson(),
            $this->authenticatorData(signCount: 1),
            'not-a-real-signature',
            'cred-1',
            $this->repositoryWith($storedSource),
        );

        self::assertSame(SecondFactorResult::NotSatisfied, $result);
        self::assertNull($verifier->getVerifiedCredential());
    }

    public function testVerifyReturnsNotSatisfiedForAnUnknownCredential(): void
    {
        $storedSource = new PublicKeyCredentialSource(
            credentialId: 'cred-other',
            publicKey: new CoseKey(algorithm: -7, parameters: [1 => 2, -1 => 1, -2 => 'x', -3 => 'y']),
            signCount: 0,
            aaguid: null,
            userHandle: 'user-1',
            transports: [],
        );

        $ceremony = new AssertionCeremony($this->relyingParty(), [-7 => new Es256Verifier()]);
        $verifier = new SecondFactorAssertionVerifier($ceremony);

        $result = $verifier->verify(
            $this->challenge(),
            $this->clientDataJson(),
            $this->authenticatorData(signCount: 1),
            'irrelevant',
            'cred-1',
            $this->repositoryWith($storedSource),
        );

        self::assertSame(SecondFactorResult::NotSatisfied, $result);
    }
}
