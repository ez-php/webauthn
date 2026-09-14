<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebAuthn\AttestationStatement\AttestationStatementVerifierRegistry;
use EzPhp\WebAuthn\AttestationStatement\NoneAttestationVerifier;
use EzPhp\WebAuthn\Cbor\CborDecoder;
use EzPhp\WebAuthn\Challenge;
use EzPhp\WebAuthn\Exception\InvalidClientDataException;
use EzPhp\WebAuthn\RegistrationCeremony;
use EzPhp\WebAuthn\RelyingParty;

/**
 * Class RegistrationCeremonyTest
 *
 * @package Tests
 */
final class RegistrationCeremonyTest extends TestCase
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
            'type' => 'webauthn.create',
            'challenge' => rtrim(strtr(base64_encode('raw-challenge-bytes'), '+/', '-_'), '='),
            'origin' => 'https://example.com',
        ]);
        self::assertIsString($json);

        return $json;
    }

    private function authenticatorData(string $flags = "\x45"): string
    {
        // Default flags: UP=1, UV=1, AT=1
        $rpIdHash = hash('sha256', 'example.com', true);
        $signCount = "\x00\x00\x00\x00";
        $aaguid = str_repeat("\x00", 16);
        $credentialId = str_repeat("\xbb", 16);
        $credentialIdLength = pack('n', strlen($credentialId));
        $coseKey = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" . str_repeat("\x01", 32) . "\x22\x58\x20" . str_repeat("\x02", 32);

        return $rpIdHash . $flags . $signCount . $aaguid . $credentialIdLength . $credentialId . $coseKey;
    }

    /**
     * @param array<string, mixed> $attStmt
     */
    private function attestationObject(string $fmt, array $attStmt, string $flags = "\x45"): string
    {
        // Minimal CBOR map encoder sufficient for this fixed 3-key map, built
        // by hand since only CborDecoder (decode direction) exists in Phase 1.
        $encodeTextString = static fn (string $s): string => chr((0x60 | strlen($s)) & 0xff) . $s;
        $encodeByteString = static fn (string $s): string => strlen($s) < 24
            ? chr(0x40 | strlen($s)) . $s
            : "\x58" . chr(strlen($s) & 0xff) . $s;

        $authData = $this->authenticatorData($flags);

        return "\xa3"
            . $encodeTextString('fmt') . $encodeTextString($fmt)
            . $encodeTextString('attStmt') . chr((0xa0 | count($attStmt)) & 0xff)
            . $encodeTextString('authData') . $encodeByteString($authData);
    }

    public function test_verifies_none_attestation_and_returns_credential_source(): void
    {
        $registry = new AttestationStatementVerifierRegistry(['none' => new NoneAttestationVerifier()]);
        $ceremony = new RegistrationCeremony($this->relyingParty(), $registry);

        $attestationObject = $this->attestationObject('none', []);

        $source = $ceremony->verify($this->challenge(), $this->clientDataJson(), $attestationObject, userHandle: 'user-1');

        self::assertSame(str_repeat("\xbb", 16), $source->credentialId);
        self::assertSame('user-1', $source->userHandle);
        self::assertSame(0, $source->signCount);
        self::assertSame(-7, $source->publicKey->algorithm);
        self::assertNotNull($source->attestationResult);
        self::assertSame('none', $source->attestationResult->attestationType);
        self::assertFalse($source->attestationResult->trusted);
    }

    public function test_rejects_a_relying_party_id_hash_mismatch(): void
    {
        $registry = new AttestationStatementVerifierRegistry(['none' => new NoneAttestationVerifier()]);
        $wrongRelyingParty = new RelyingParty(id: 'other.example', name: 'Other', allowedOrigins: ['https://example.com']);
        $ceremony = new RegistrationCeremony($wrongRelyingParty, $registry);

        $attestationObject = $this->attestationObject('none', []);

        $this->expectException(InvalidClientDataException::class);

        $ceremony->verify($this->challenge(), $this->clientDataJson(), $attestationObject, userHandle: 'user-1');
    }

    public function test_rejects_missing_user_presence_flag(): void
    {
        $registry = new AttestationStatementVerifierRegistry(['none' => new NoneAttestationVerifier()]);
        $ceremony = new RegistrationCeremony($this->relyingParty(), $registry);

        // UP=0, UV=1, AT=1 (0x44) — user presence flag cleared.
        $attestationObject = $this->attestationObject('none', [], flags: "\x44");

        $this->expectException(InvalidClientDataException::class);
        $this->expectExceptionMessage('authenticatorData does not report user presence.');

        $ceremony->verify($this->challenge(), $this->clientDataJson(), $attestationObject, userHandle: 'user-1');
    }
}
