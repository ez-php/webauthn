<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn;

/**
 * Application-implemented credential persistence. This module never
 * persists state itself.
 *
 * @package EzPhp\WebAuthn
 */
interface CredentialRepositoryInterface
{
    public function findByCredentialId(string $credentialId): ?PublicKeyCredentialSource;

    /**
     * @return list<PublicKeyCredentialSource>
     */
    public function findByUserHandle(string $userHandle): array;

    public function save(PublicKeyCredentialSource $source): void;
}
