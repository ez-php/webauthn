<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebAuthn\AuthenticatorData;

/**
 * Class AuthenticatorDataTest
 *
 * @package Tests
 */
final class AuthenticatorDataTest extends TestCase
{
    public function test_parses_flags_and_sign_count_without_attested_credential_data(): void
    {
        $rpIdHash = hash('sha256', 'example.com', true);
        $flags = "\x01"; // UP=1, UV=0, AT=0
        $signCount = "\x00\x00\x00\x05";

        $data = AuthenticatorData::parse($rpIdHash . $flags . $signCount);

        self::assertSame($rpIdHash, $data->rpIdHash);
        self::assertTrue($data->userPresent);
        self::assertFalse($data->userVerified);
        self::assertSame(5, $data->signCount);
        self::assertNull($data->credentialId);
        self::assertNull($data->credentialPublicKey);
    }

    public function test_parses_attested_credential_data_when_flag_is_set(): void
    {
        $rpIdHash = hash('sha256', 'example.com', true);
        $flags = "\x45"; // UP=1, UV=1, AT=1 (0x01 | 0x04 | 0x40)
        $signCount = "\x00\x00\x00\x01";
        $aaguid = str_repeat("\x00", 16);
        $credentialId = "\xaa\xbb\xcc";
        $credentialIdLength = "\x00\x03";
        // Minimal ES256 COSE_Key CBOR map: {1: 2, 3: -7, -1: 1, -2: h'01', -3: h'02'}
        $coseKey = "\xa5\x01\x02\x03\x26\x20\x01\x21\x41\x01\x22\x41\x02";

        $data = AuthenticatorData::parse($rpIdHash . $flags . $signCount . $aaguid . $credentialIdLength . $credentialId . $coseKey);

        self::assertTrue($data->userVerified);
        self::assertSame($aaguid, $data->aaguid);
        self::assertSame($credentialId, $data->credentialId);
        self::assertNotNull($data->credentialPublicKey);
        self::assertSame(-7, $data->credentialPublicKey->algorithm);
    }

    public function test_throws_on_truncated_input(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        AuthenticatorData::parse('too short');
    }

    public function test_throws_when_claimed_credential_id_length_exceeds_maximum(): void
    {
        $rpIdHash = hash('sha256', 'example.com', true);
        $flags = "\x45"; // UP=1, UV=1, AT=1
        $signCount = "\x00\x00\x00\x01";
        $aaguid = str_repeat("\x00", 16);
        $credentialIdLength = pack('n', 2000); // exceeds the 1023-byte spec cap

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Credential ID exceeds the maximum allowed length.');

        AuthenticatorData::parse($rpIdHash . $flags . $signCount . $aaguid . $credentialIdLength);
    }
}
