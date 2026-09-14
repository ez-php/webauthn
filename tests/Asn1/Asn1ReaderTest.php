<?php

declare(strict_types=1);

namespace Tests\Asn1;

use EzPhp\WebAuthn\Asn1\Asn1Reader;
use Tests\TestCase;

/**
 * Class Asn1ReaderTest
 *
 * @package Tests\Asn1
 */
final class Asn1ReaderTest extends TestCase
{
    public function test_reads_a_short_form_tlv(): void
    {
        // OCTET STRING, length 4, content "\x01\x02\x03\x04"
        $tlv = Asn1Reader::readTlv("\x04\x04\x01\x02\x03\x04", 0);

        self::assertSame(0x04, $tlv['tag']);
        self::assertSame("\x01\x02\x03\x04", $tlv['value']);
        self::assertSame(6, $tlv['nextOffset']);
    }

    public function test_reads_a_long_form_length(): void
    {
        $content = str_repeat("\xaa", 200);
        // OCTET STRING, long-form length: 0x81 0xc8 (200 in one length-octet)
        $tlv = Asn1Reader::readTlv("\x04\x81\xc8" . $content, 0);

        self::assertSame($content, $tlv['value']);
        self::assertSame(203, $tlv['nextOffset']);
    }

    public function test_reads_sequence_elements(): void
    {
        // SEQUENCE { INTEGER 5, OCTET STRING "ab" }
        $sequence = "\x30\x07" . "\x02\x01\x05" . "\x04\x02ab";

        $elements = Asn1Reader::readSequenceElements($sequence);

        self::assertCount(2, $elements);
        self::assertSame(0x02, $elements[0]['tag']);
        self::assertSame("\x05", $elements[0]['value']);
        self::assertSame(0x04, $elements[1]['tag']);
        self::assertSame('ab', $elements[1]['value']);
    }

    public function test_rejects_a_non_sequence_outer_tag(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Asn1Reader::readSequenceElements("\x04\x02ab");
    }

    public function test_throws_on_truncated_input(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Asn1Reader::readTlv("\x04\x05ab", 0); // declares length 5, only 2 bytes follow
    }
}
