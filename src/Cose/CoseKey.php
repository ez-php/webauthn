<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Cose;

use EzPhp\WebAuthn\Cbor\CborDecoder;

/**
 * A parsed COSE_Key (RFC 9053) as emitted inside WebAuthn attestation and
 * authenticator data. Only the labels WebAuthn actually uses are validated;
 * everything else is preserved verbatim in $parameters for the algorithm
 * verifiers (Cose\Verifier\*) to read.
 *
 * @package EzPhp\WebAuthn\Cose
 */
final readonly class CoseKey
{
    /**
     * @param array<int, mixed> $parameters raw decoded COSE_Key map, keyed by COSE label
     */
    public function __construct(
        public int $algorithm,
        public array $parameters,
    ) {
    }

    public static function fromCbor(string $cborBytes): self
    {
        $decoded = CborDecoder::decode($cborBytes);

        if (!is_array($decoded)) {
            throw new \InvalidArgumentException('COSE_Key must decode to a CBOR map.');
        }

        $algorithm = $decoded[3] ?? null;

        if (!is_int($algorithm)) {
            throw new \InvalidArgumentException('COSE_Key is missing the algorithm label (3).');
        }

        /** @var array<int, mixed> $decoded */
        return new self(algorithm: $algorithm, parameters: $decoded);
    }

    /**
     * PEM-encode an EC (kty=2) or RSA (kty=3) public key. OKP (kty=1, e.g.
     * Ed25519) keys are verified from raw coordinate bytes instead — see
     * Cose\Verifier\EdDsaVerifier — and are not representable this way.
     *
     * @throws \InvalidArgumentException for an unsupported or OKP key type
     */
    public function toPem(): string
    {
        $keyType = $this->parameters[1] ?? null;

        if (!is_int($keyType)) {
            throw new \InvalidArgumentException('Cannot PEM-encode COSE key: missing or invalid key type.');
        }

        return match ($keyType) {
            2 => $this->ecPublicKeyToPem(),
            3 => $this->rsaPublicKeyToPem(),
            default => throw new \InvalidArgumentException("Cannot PEM-encode COSE key type: {$keyType}"),
        };
    }

    private function ecPublicKeyToPem(): string
    {
        $curve = $this->parameters[-1] ?? null;

        if ($curve !== 1) {
            throw new \InvalidArgumentException('Only P-256 (crv=1) EC keys are supported.');
        }

        $x = $this->parameters[-2] ?? null;
        $y = $this->parameters[-3] ?? null;

        if (!is_string($x) || !is_string($y)) {
            throw new \InvalidArgumentException('EC COSE key is missing x/y coordinates.');
        }

        // openssl_pkey_get_details() returns EC coordinates as minimal-length
        // big-endian octet strings — a coordinate with a leading zero byte
        // comes back shorter than the curve's fixed 32-byte field width, so
        // it must be re-padded before building a fixed-width SEC1 point.
        $x = str_pad($x, 32, "\x00", STR_PAD_LEFT);
        $y = str_pad($y, 32, "\x00", STR_PAD_LEFT);

        if (strlen($x) !== 32 || strlen($y) !== 32) {
            throw new \InvalidArgumentException('EC COSE key x/y coordinates exceed the P-256 field width.');
        }

        // Uncompressed SEC1 point: 0x04 || x || y, wrapped in a P-256
        // SubjectPublicKeyInfo DER structure (fixed prefix for prime256v1).
        $point = "\x04" . $x . $y;
        $prefix = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200');

        if ($prefix === false) {
            throw new \InvalidArgumentException('Failed to build EC SPKI prefix.');
        }

        $der = $prefix . $point;

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private function rsaPublicKeyToPem(): string
    {
        $modulus = $this->parameters[-1] ?? null;
        $exponent = $this->parameters[-2] ?? null;

        if (!is_string($modulus) || !is_string($exponent)) {
            throw new \InvalidArgumentException('RSA COSE key is missing modulus/exponent.');
        }

        if (strlen($modulus) < 128 || strlen($modulus) > 1024) {
            throw new \InvalidArgumentException('RSA COSE key modulus size is out of the supported range (128-1024 bytes).');
        }

        if (strlen($exponent) > 8) {
            throw new \InvalidArgumentException('RSA COSE key exponent exceeds the supported size (8 bytes).');
        }

        $der = self::derSequence(
            self::derInteger($modulus) . self::derInteger($exponent),
        );

        // Wrap the RSAPublicKey SEQUENCE in a SubjectPublicKeyInfo structure.
        $algorithmIdentifier = hex2bin('300d06092a864886f70d0101010500');

        if ($algorithmIdentifier === false) {
            throw new \InvalidArgumentException('Failed to build RSA algorithm identifier.');
        }

        $bitString = "\x03" . self::derLength(strlen($der) + 1) . "\x00" . $der;
        $spki = self::derSequence($algorithmIdentifier . $bitString);

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function derInteger(string $unsignedBigEndian): string
    {
        // Prepend a zero byte if the high bit is set, so DER doesn't read it as negative.
        if ($unsignedBigEndian !== '' && (ord($unsignedBigEndian[0]) & 0x80) !== 0) {
            $unsignedBigEndian = "\x00" . $unsignedBigEndian;
        }

        return "\x02" . self::derLength(strlen($unsignedBigEndian)) . $unsignedBigEndian;
    }

    private static function derSequence(string $content): string
    {
        return "\x30" . self::derLength(strlen($content)) . $content;
    }

    private static function derLength(int $length): string
    {
        if ($length < 0) {
            throw new \InvalidArgumentException('DER length cannot be negative.');
        }

        if ($length < 128) {
            return chr($length);
        }

        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xff) . $bytes;
            $length >>= 8;
        }

        $byteCount = strlen($bytes);

        if ($byteCount > 127) {
            throw new \InvalidArgumentException('DER length is too large to encode.');
        }

        return chr(0x80 | $byteCount) . $bytes;
    }
}
