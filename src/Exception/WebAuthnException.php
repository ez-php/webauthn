<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Exception;

/**
 * Base type for every exception this module throws. Concrete subclasses are
 * final; this base exists specifically to be extended (documented
 * exception-hierarchy carve-out per root CLAUDE.md).
 *
 * @package EzPhp\WebAuthn\Exception
 */
abstract class WebAuthnException extends \RuntimeException
{
}
