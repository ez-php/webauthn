<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebAuthn\AssertionCeremony;
use EzPhp\WebAuthn\Challenge;
use EzPhp\WebAuthn\Cose\CoseKey;
use EzPhp\WebAuthn\Cose\Verifier\Es256Verifier;
use EzPhp\WebAuthn\CredentialRepositoryInterface;
use EzPhp\WebAuthn\Exception\SignatureCounterException;
use EzPhp\WebAuthn\Exception\SignatureVerificationException;
use EzPhp\WebAuthn\PublicKeyCredentialSource;
use EzPhp\WebAuthn\RelyingParty;

/**
 * Class AssertionCeremonyTest
 *
 * @package Tests
 */
final class AssertionCeremonyTest extends TestCase
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
        $flags = "\x01"; // UP=1, UV=0, AT=0 (no attested credential data in an assertion)

        return $rpIdHash . $flags . pack('N', $signCount);
    }

    /**
     * @return CredentialRepositoryInterface&object{saved: ?PublicKeyCredentialSource}
     */
    private function repositoryWith(PublicKeyCredentialSource $source): CredentialRepositoryInterface
    {
        return new class ($source) implements CredentialRepositoryInterface {
            public ?PublicKeyCredentialSource $saved = null;

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
                $this->saved = $source;
            }
        };
    }

    public function test_verifies_a_valid_assertion_and_updates_sign_count(): void
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
        $repository = $this->repositoryWith($storedSource);

        $result = $ceremony->verify($this->challenge(), $clientDataJson, $authenticatorData, $signature, 'cred-1', $repository);

        self::assertSame(4, $result->signCount);
    }

    public function test_rejects_a_non_increasing_signature_counter(): void
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
            signCount: 5,
            aaguid: null,
            userHandle: 'user-1',
            transports: [],
        );

        $clientDataJson = $this->clientDataJson();
        $authenticatorData = $this->authenticatorData(signCount: 5); // not strictly greater than stored 5
        $clientDataHash = hash('sha256', $clientDataJson, true);
        openssl_sign($authenticatorData . $clientDataHash, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $ceremony = new AssertionCeremony($this->relyingParty(), [-7 => new Es256Verifier()]);

        $this->expectException(SignatureCounterException::class);

        $ceremony->verify($this->challenge(), $clientDataJson, $authenticatorData, $signature, 'cred-1', $this->repositoryWith($storedSource));
    }

    public function test_rejects_a_credential_bound_to_a_different_user(): void
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
            userHandle: 'user-A',
            transports: [],
        );

        $clientDataJson = $this->clientDataJson();
        $authenticatorData = $this->authenticatorData(signCount: 1);
        $clientDataHash = hash('sha256', $clientDataJson, true);
        openssl_sign($authenticatorData . $clientDataHash, $signature, $keyPair, OPENSSL_ALGO_SHA256);

        $ceremony = new AssertionCeremony($this->relyingParty(), [-7 => new Es256Verifier()]);

        $this->expectException(\EzPhp\WebAuthn\Exception\InvalidClientDataException::class);

        $ceremony->verify(
            $this->challenge(),
            $clientDataJson,
            $authenticatorData,
            $signature,
            'cred-1',
            $this->repositoryWith($storedSource),
            expectedUserHandle: 'user-B',
        );
    }

    public function test_rejects_an_invalid_signature(): void
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

        $this->expectException(SignatureVerificationException::class);

        $ceremony->verify(
            $this->challenge(),
            $this->clientDataJson(),
            $this->authenticatorData(signCount: 1),
            'not-a-real-signature',
            'cred-1',
            $this->repositoryWith($storedSource),
        );
    }
}
