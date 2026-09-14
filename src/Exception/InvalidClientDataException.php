<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Exception;

/**
 * Thrown when clientDataJSON fails type/challenge/origin verification.
 *
 * @package EzPhp\WebAuthn\Exception
 */
final class InvalidClientDataException extends WebAuthnException
{
}
