<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Exception;

/**
 * Thrown when an assertion's signature counter does not strictly increase
 * from a nonzero previously-stored value (clone detection).
 *
 * @package EzPhp\WebAuthn\Exception
 */
final class SignatureCounterException extends WebAuthnException
{
}
