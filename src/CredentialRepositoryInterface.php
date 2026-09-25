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
    /**
     * Find a stored credential by its credential ID, or null when unknown.
     */
    public function findByCredentialId(string $credentialId): ?PublicKeyCredentialSource;

    /**
     * @return list<PublicKeyCredentialSource>
     */
    public function findByUserHandle(string $userHandle): array;

    /**
     * Persist a credential source (insert or update by credential ID).
     */
    public function save(PublicKeyCredentialSource $source): void;
}
