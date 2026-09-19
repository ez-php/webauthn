<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn;

use EzPhp\Contracts\SecondFactorResult;
use EzPhp\WebAuthn\Exception\WebAuthnException;

/**
 * Wraps AssertionCeremony::verify() to report its outcome as the shared
 * EzPhp\Contracts\SecondFactorResult type, so application-level login-flow
 * code can branch on one result regardless of whether the second factor was
 * a WebAuthn passkey or, e.g., `ez-php/two-factor`'s TOTP codes.
 *
 * `ez-php/contracts` is only a require-dev (soft) dependency of this
 * package — PSR-4 resolves the class only when something actually
 * references it, so this file can ship in `src/` without pulling
 * `ez-php/contracts` into a standalone install that never uses it, keeping
 * the rest of the module framework-agnostic (same reasoning as
 * `ez-php/mail`'s `Job\SendMailableJob`).
 *
 * This class does not replace AssertionCeremony — it does not merge the
 * `ez-php/webauthn` and `ez-php/two-factor` modules, which remain mutually
 * exclusive as documented in both modules' CLAUDE.md. It only adapts one
 * ceremony's result to a shared outcome type.
 *
 * @package EzPhp\WebAuthn
 */
final class SecondFactorAssertionVerifier
{
    private ?PublicKeyCredentialSource $verifiedCredential = null;

    /**
     * @param AssertionCeremony $ceremony
     */
    public function __construct(private readonly AssertionCeremony $ceremony)
    {
    }

    /**
     * Verify a WebAuthn assertion and report the outcome.
     *
     * On success, the updated `PublicKeyCredentialSource` (with its new
     * signature counter) is retained and available via
     * `getVerifiedCredential()` — the caller must still persist it, exactly
     * as when calling `AssertionCeremony::verify()` directly, since the
     * `SecondFactorResult` return value alone carries no credential state.
     *
     * @param Challenge                     $challenge
     * @param string                        $clientDataJson
     * @param string                        $authenticatorData
     * @param string                        $signature
     * @param string                        $credentialId
     * @param CredentialRepositoryInterface $credentials
     * @param string|null                   $expectedUserHandle
     *
     * @return SecondFactorResult
     */
    public function verify(
        Challenge $challenge,
        string $clientDataJson,
        string $authenticatorData,
        string $signature,
        string $credentialId,
        CredentialRepositoryInterface $credentials,
        ?string $expectedUserHandle = null,
    ): SecondFactorResult {
        try {
            $this->verifiedCredential = $this->ceremony->verify(
                $challenge,
                $clientDataJson,
                $authenticatorData,
                $signature,
                $credentialId,
                $credentials,
                $expectedUserHandle,
            );
        } catch (WebAuthnException) {
            $this->verifiedCredential = null;

            return SecondFactorResult::NotSatisfied;
        }

        return SecondFactorResult::Satisfied;
    }

    /**
     * Return the verified credential from the most recent successful
     * `verify()` call, or null if the last call failed (or none was made).
     *
     * @return PublicKeyCredentialSource|null
     */
    public function getVerifiedCredential(): ?PublicKeyCredentialSource
    {
        return $this->verifiedCredential;
    }
}
