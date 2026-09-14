<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Cbor;

/**
 * Minimal CBOR (RFC 8949) decoder scoped to the major types WebAuthn
 * authenticators actually emit in attestationObject / authenticatorData.
 * Not a general-purpose CBOR implementation.
 *
 * @package EzPhp\WebAuthn\Cbor
 */
final class CborDecoder
{
    /**
     * Decode exactly one CBOR data item starting at offset 0 of $bytes.
     *
     * @throws \InvalidArgumentException on malformed or unsupported input
     */
    public static function decode(string $bytes): mixed
    {
        $offset = 0;
        $value = self::decodeItem($bytes, $offset);

        return $value;
    }

    private static function decodeItem(string $bytes, int &$offset): mixed
    {
        if (!isset($bytes[$offset])) {
            throw new \InvalidArgumentException('Unexpected end of CBOR input.');
        }

        $initialByte = ord($bytes[$offset]);
        $majorType = $initialByte >> 5;
        $additionalInfo = $initialByte & 0x1f;
        $offset++;

        return match ($majorType) {
            0 => self::readUnsignedInt($bytes, $offset, $additionalInfo),
            1 => -1 - self::readUnsignedInt($bytes, $offset, $additionalInfo),
            2 => self::readByteString($bytes, $offset, $additionalInfo),
            3 => self::readByteString($bytes, $offset, $additionalInfo),
            4 => self::readArray($bytes, $offset, $additionalInfo),
            5 => self::readMap($bytes, $offset, $additionalInfo),
            7 => self::readSimpleOrFloat($bytes, $offset, $additionalInfo),
            default => throw new \InvalidArgumentException("Unsupported CBOR major type: {$majorType}"),
        };
    }

    private static function readUnsignedInt(string $bytes, int &$offset, int $additionalInfo): int
    {
        if ($additionalInfo < 24) {
            return $additionalInfo;
        }

        $length = match ($additionalInfo) {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            default => throw new \InvalidArgumentException("Unsupported CBOR length indicator: {$additionalInfo}"),
        };

        $chunk = substr($bytes, $offset, $length);

        if (strlen($chunk) !== $length) {
            throw new \InvalidArgumentException('Unexpected end of CBOR input while reading integer.');
        }

        $offset += $length;

        // Unpack as a big-endian unsigned integer rather than building the
        // value with manual shifts: a CBOR-encoded value >= 2^63 wraps to a
        // negative PHP int (PHP ints are signed 64-bit), and unpack()'s
        // return type isn't statically narrowed to non-negative the way a
        // hand-rolled shift/OR loop would appear to be, so the overflow
        // check below is not dead code.
        $format = match ($length) {
            1 => 'C',
            2 => 'n',
            4 => 'N',
            default => 'J',
        };

        $unpacked = unpack($format, $chunk);

        if ($unpacked === false) {
            throw new \InvalidArgumentException('Failed to read CBOR integer.');
        }

        $value = $unpacked[1];

        if ($value < 0) {
            throw new \InvalidArgumentException('CBOR length/count exceeds supported range.');
        }

        return $value;
    }

    private static function readByteString(string $bytes, int &$offset, int $additionalInfo): string
    {
        $length = self::readUnsignedInt($bytes, $offset, $additionalInfo);
        self::assertLengthWithinRemainingInput($bytes, $offset, $length);
        $value = substr($bytes, $offset, $length);

        if (strlen($value) !== $length) {
            throw new \InvalidArgumentException('Unexpected end of CBOR input while reading string.');
        }

        $offset += $length;

        return $value;
    }

    /**
     * @return list<mixed>
     */
    private static function readArray(string $bytes, int &$offset, int $additionalInfo): array
    {
        $count = self::readUnsignedInt($bytes, $offset, $additionalInfo);
        self::assertLengthWithinRemainingInput($bytes, $offset, $count);
        $items = [];

        for ($i = 0; $i < $count; $i++) {
            $items[] = self::decodeItem($bytes, $offset);
        }

        return $items;
    }

    /**
     * @return array<int|string, mixed>
     */
    private static function readMap(string $bytes, int &$offset, int $additionalInfo): array
    {
        $count = self::readUnsignedInt($bytes, $offset, $additionalInfo);
        self::assertLengthWithinRemainingInput($bytes, $offset, $count);
        $map = [];

        for ($i = 0; $i < $count; $i++) {
            $key = self::decodeItem($bytes, $offset);

            if (!is_int($key) && !is_string($key)) {
                throw new \InvalidArgumentException('CBOR map keys must be integers or strings.');
            }

            if (array_key_exists($key, $map)) {
                throw new \InvalidArgumentException('CBOR map contains a duplicate key.');
            }

            $map[$key] = self::decodeItem($bytes, $offset);
        }

        return $map;
    }

    /**
     * No CBOR item can be shorter than 1 byte, so a decoded length/count that
     * exceeds the remaining input can never be legitimate — reject it here
     * rather than letting it silently desync the parser.
     */
    private static function assertLengthWithinRemainingInput(string $bytes, int $offset, int $length): void
    {
        if ($length > strlen($bytes) - $offset) {
            throw new \InvalidArgumentException('CBOR length/count exceeds remaining input.');
        }
    }

    private static function readSimpleOrFloat(string $bytes, int &$offset, int $additionalInfo): bool|null|float
    {
        return match ($additionalInfo) {
            20 => false,
            21 => true,
            22 => null,
            27 => self::readDouble($bytes, $offset),
            default => throw new \InvalidArgumentException("Unsupported CBOR simple/float value: {$additionalInfo}"),
        };
    }

    private static function readDouble(string $bytes, int &$offset): float
    {
        $chunk = substr($bytes, $offset, 8);

        if (strlen($chunk) !== 8) {
            throw new \InvalidArgumentException('Unexpected end of CBOR input while reading double.');
        }

        $offset += 8;

        /** @var array{1: float} $unpacked */
        $unpacked = unpack('E', $chunk);

        return $unpacked[1];
    }
}
