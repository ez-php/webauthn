<?php

declare(strict_types=1);

namespace EzPhp\WebAuthn\Asn1;

/**
 * Minimal DER (Distinguished Encoding Rules) reader scoped to exactly what
 * this module needs: reading one tag-length-value, and walking a SEQUENCE's
 * immediate children. Not a general ASN.1/DER library — no OID decoding, no
 * BIT STRING unwrapping, no indefinite-length BER support.
 *
 * @package EzPhp\WebAuthn\Asn1
 */
final class Asn1Reader
{
    /**
     * @return array{tag: int, value: string, nextOffset: int}
     */
    public static function readTlv(string $bytes, int $offset): array
    {
        if (!isset($bytes[$offset])) {
            throw new \InvalidArgumentException('Unexpected end of DER input while reading a tag.');
        }

        $tag = ord($bytes[$offset]);
        $offset++;

        if (!isset($bytes[$offset])) {
            throw new \InvalidArgumentException('Unexpected end of DER input while reading a length.');
        }

        $lengthByte = ord($bytes[$offset]);
        $offset++;

        if ($lengthByte < 0x80) {
            $length = $lengthByte;
        } else {
            $numLengthOctets = $lengthByte & 0x7f;

            if ($numLengthOctets === 0 || $numLengthOctets > 4) {
                throw new \InvalidArgumentException('Unsupported DER length encoding.');
            }

            $lengthBytes = substr($bytes, $offset, $numLengthOctets);

            if (strlen($lengthBytes) !== $numLengthOctets) {
                throw new \InvalidArgumentException('Unexpected end of DER input while reading a long-form length.');
            }

            $offset += $numLengthOctets;
            $length = 0;

            for ($i = 0; $i < $numLengthOctets; $i++) {
                $length = ($length << 8) | ord($lengthBytes[$i]);
            }
        }

        if ($offset + $length > strlen($bytes)) {
            throw new \InvalidArgumentException('DER length exceeds remaining input.');
        }

        $value = substr($bytes, $offset, $length);

        return ['tag' => $tag, 'value' => $value, 'nextOffset' => $offset + $length];
    }

    /**
     * @return list<array{tag: int, value: string}>
     */
    public static function readSequenceElements(string $sequenceTlv): array
    {
        $outer = self::readTlv($sequenceTlv, 0);

        if ($outer['tag'] !== 0x30) {
            throw new \InvalidArgumentException('Expected a DER SEQUENCE (tag 0x30).');
        }

        $elements = [];
        $content = $outer['value'];
        $offset = 0;

        while ($offset < strlen($content)) {
            $item = self::readTlv($content, $offset);
            $elements[] = ['tag' => $item['tag'], 'value' => $item['value']];
            $offset = $item['nextOffset'];
        }

        return $elements;
    }
}
