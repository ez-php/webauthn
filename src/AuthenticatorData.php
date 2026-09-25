<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn;

use EzPhp\WebAuthn\Cose\CoseKey;

/**
 * Parsed authenticatorData structure (WebAuthn spec §6.1): RP ID hash, flags,
 * signature counter, and — for registration ceremonies — the attested
 * credential data (AAGUID, credential ID, COSE public key).
 *
 * @package EzPhp\WebAuthn
 */
final readonly class AuthenticatorData
{
    private const int FLAG_USER_PRESENT = 0x01;
    private const int FLAG_USER_VERIFIED = 0x04;
    private const int FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;

    /**
     * AuthenticatorData Constructor
     *
     * @param string       $rpIdHash
     * @param bool         $userPresent
     * @param bool         $userVerified
     * @param int          $signCount
     * @param string|null  $aaguid
     * @param string|null  $credentialId
     * @param CoseKey|null $credentialPublicKey
     */
    public function __construct(
        public string $rpIdHash,
        public bool $userPresent,
        public bool $userVerified,
        public int $signCount,
        public ?string $aaguid,
        public ?string $credentialId,
        public ?CoseKey $credentialPublicKey,
    ) {
    }

    /**
     * Parse raw authenticator data bytes.
     */
    public static function parse(string $bytes): self
    {
        if (strlen($bytes) < 37) {
            throw new \InvalidArgumentException('authenticatorData must be at least 37 bytes.');
        }

        $rpIdHash = substr($bytes, 0, 32);
        $flags = ord($bytes[32]);
        $signCount = unpack('N', substr($bytes, 33, 4));

        if ($signCount === false) {
            throw new \InvalidArgumentException('Failed to read authenticatorData sign count.');
        }

        $userPresent = ($flags & self::FLAG_USER_PRESENT) !== 0;
        $userVerified = ($flags & self::FLAG_USER_VERIFIED) !== 0;
        $hasAttestedCredentialData = ($flags & self::FLAG_ATTESTED_CREDENTIAL_DATA) !== 0;

        $aaguid = null;
        $credentialId = null;
        $credentialPublicKey = null;

        if ($hasAttestedCredentialData) {
            if (strlen($bytes) < 37 + 16 + 2) {
                throw new \InvalidArgumentException('authenticatorData is truncated before attested credential data.');
            }

            $aaguid = substr($bytes, 37, 16);
            $credentialIdLength = unpack('n', substr($bytes, 53, 2));

            if ($credentialIdLength === false) {
                throw new \InvalidArgumentException('Failed to read credential ID length.');
            }

            $length = $credentialIdLength[1];

            if ($length > 1023) {
                throw new \InvalidArgumentException('Credential ID exceeds the maximum allowed length.');
            }

            $credentialId = substr($bytes, 55, $length);

            if (strlen($credentialId) !== $length) {
                throw new \InvalidArgumentException('authenticatorData is truncated within the credential ID.');
            }

            $coseKeyBytes = substr($bytes, 55 + $length);
            $credentialPublicKey = CoseKey::fromCbor($coseKeyBytes);
        }

        return new self(
            rpIdHash: $rpIdHash,
            userPresent: $userPresent,
            userVerified: $userVerified,
            signCount: $signCount[1],
            aaguid: $aaguid,
            credentialId: $credentialId,
            credentialPublicKey: $credentialPublicKey,
        );
    }
}
