<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Tpm;

/**
 * A parsed TPM 2.0 TPMS_ATTEST structure of type TPM_ST_ATTEST_CERTIFY.
 *
 * @package EzPhp\WebAuthn\Tpm
 */
final readonly class TpmsAttest
{
    /**
     * TpmsAttest Constructor
     *
     * @param int    $magic
     * @param int    $type
     * @param string $extraData
     * @param string $attestedNameAlgId
     * @param string $attestedNameHash
     */
    public function __construct(
        public int $magic,
        public int $type,
        public string $extraData,
        public string $attestedNameAlgId,
        public string $attestedNameHash,
    ) {
    }
}
