<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Exception;

/**
 * Thrown when an assertion signature fails verification against the stored
 * public key.
 *
 * @package EzPhp\WebAuthn\Exception
 */
final class SignatureVerificationException extends WebAuthnException
{
}
