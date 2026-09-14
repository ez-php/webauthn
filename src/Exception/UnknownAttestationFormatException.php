<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Exception;

/**
 * Thrown when an attestation statement's `fmt` has no registered verifier.
 *
 * @package EzPhp\WebAuthn\Exception
 */
final class UnknownAttestationFormatException extends WebAuthnException
{
}
