<?php

declare(strict_types=1);

namespace Tests\Cbor;

use EzPhp\WebAuthn\Cbor\CborDecoder;
use Tests\TestCase;

/**
 * Class CborDecoderTest
 *
 * @package Tests\Cbor
 */
final class CborDecoderTest extends TestCase
{
    public function test_decodes_small_unsigned_integer(): void
    {
        self::assertSame(10, CborDecoder::decode("\x0a"));
    }

    public function test_decodes_unsigned_integer_with_one_byte_payload(): void
    {
        self::assertSame(25, CborDecoder::decode("\x18\x19"));
    }

    public function test_decodes_negative_integer(): void
    {
        self::assertSame(-1, CborDecoder::decode("\x20"));
        self::assertSame(-10, CborDecoder::decode("\x29"));
    }

    public function test_decodes_byte_string(): void
    {
        self::assertSame("\x01\x02\x03\x04", CborDecoder::decode("\x44\x01\x02\x03\x04"));
    }

    public function test_decodes_text_string(): void
    {
        self::assertSame('IETF', CborDecoder::decode("\x64IETF"));
    }

    public function test_decodes_array(): void
    {
        self::assertSame([1, 2, 3], CborDecoder::decode("\x83\x01\x02\x03"));
    }

    public function test_decodes_map_with_integer_and_string_keys(): void
    {
        self::assertSame([1 => 2, 'a' => 'b'], CborDecoder::decode("\xa2\x01\x02\x61\x61\x61\x62"));
    }

    public function test_decodes_true_false_and_null(): void
    {
        self::assertTrue(CborDecoder::decode("\xf5"));
        self::assertFalse(CborDecoder::decode("\xf4"));
        self::assertNull(CborDecoder::decode("\xf6"));
    }

    public function test_decodes_double_precision_float(): void
    {
        self::assertSame(1.5, CborDecoder::decode("\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00"));
    }

    public function test_throws_on_empty_input(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        CborDecoder::decode('');
    }

    public function test_throws_on_byte_string_length_overflow(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // Byte string, 8-byte length = 2^64-1 (overflows to a negative PHP int).
        CborDecoder::decode("\x5b\xff\xff\xff\xff\xff\xff\xff\xff");
    }

    public function test_throws_on_array_count_overflow(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // Array, 8-byte count = 2^64-1 (overflows to a negative PHP int).
        CborDecoder::decode("\x9b\xff\xff\xff\xff\xff\xff\xff\xff");
    }

    public function test_throws_on_map_count_overflow(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // Map, 8-byte count = 2^63 (overflows to a negative PHP int).
        CborDecoder::decode("\xbb\x80\x00\x00\x00\x00\x00\x00\x00");
    }

    public function test_throws_on_byte_string_length_exceeding_remaining_input(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // Byte string claiming a 1-byte length of 10, but only one byte follows.
        CborDecoder::decode("\x4a\x01");
    }

    public function test_throws_on_duplicate_map_key(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('CBOR map contains a duplicate key.');

        // map(2){1: 2, 1: 3}
        CborDecoder::decode("\xa2\x01\x02\x01\x03");
    }
}
