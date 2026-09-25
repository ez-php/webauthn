<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn;

use EzPhp\WebAuthn\AttestationStatement\AttestationResult;
use EzPhp\WebAuthn\Cose\CoseKey;

/**
 * A registered WebAuthn credential as the application persists it. Returned
 * by RegistrationCeremony for the app to save via
 * CredentialRepositoryInterface::save(), and returned again (with an
 * updated sign count) by AssertionCeremony after a successful assertion.
 *
 * @package EzPhp\WebAuthn
 */
final readonly class PublicKeyCredentialSource
{
    /**
     * @param list<string> $transports
     */
    public function __construct(
        public string $credentialId,
        public CoseKey $publicKey,
        public int $signCount,
        public ?string $aaguid,
        public string $userHandle,
        public array $transports,
        public ?AttestationResult $attestationResult = null,
    ) {
    }

    /**
     * Return a copy with the given signature counter.
     */
    public function withSignCount(int $signCount): self
    {
        return new self(
            credentialId: $this->credentialId,
            publicKey: $this->publicKey,
            signCount: $signCount,
            aaguid: $this->aaguid,
            userHandle: $this->userHandle,
            transports: $this->transports,
            attestationResult: $this->attestationResult,
        );
    }
}
