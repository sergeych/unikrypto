package net.sergeych.unikrypto

/**
 * Safe58 code is a binary data to text encoder/decoder. It consist only of visually different letters and
 * digits that simplify manual code entry. It also substitutes visually alike character (like O and O, I and 1)
 * on decode (unless strict mode is requested) so such type of mistypes are autocorrected.
 */
object Safe58 {
    private val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        .toCharArray()
    private val BASE_58 = ALPHABET.size
    private const val BASE_256 = 256
    private val INDEXES = IntArray(128)

    init {
        for (i in INDEXES.indices) {
            INDEXES[i] = -1
        }
        for (i in ALPHABET.indices) {
            INDEXES[ALPHABET[i].code] = i
        }
    }

    fun encode(_input: ByteArray): String {
        if (_input.size == 0) {
            // paying with the same coin
            return ""
        }

        //
        // Make a copy of the input since we are going to modify it.
        //
        val input = _input.copyOf()

        //
        // Count leading zeroes
        //
        var zeroCount = 0
        while (zeroCount < input.size && input[zeroCount].toInt() == 0) {
            ++zeroCount
        }

        //
        // The actual encoding
        //
        val temp = ByteArray(input.size * 2)
        var j = temp.size
        var startAt = zeroCount
        while (startAt < input.size) {
            val mod = divmod58(input, startAt)
            if (input[startAt].toInt() == 0) {
                ++startAt
            }
            temp[--j] = ALPHABET[mod.toInt()].code.toByte()
        }

        //
        // Strip extra '1' if any
        //
        while (j < temp.size && temp[j] == ALPHABET[0].code.toByte()) {
            ++j
        }

        //
        // Add as many leading '1' as there were leading zeros.
        //
        while (--zeroCount >= 0) {
            temp[--j] = ALPHABET[0].code.toByte()
        }
        val output = copyOfRange(temp, j, temp.size)
        return output.decodeToString()
    }

    fun decode(_input: String, strict: Boolean = false): ByteArray {
        val input = if (!strict) {
            _input
                .replace('I', '1')
                .replace('!', '1')
                .replace('|', '1')
                .replace('l', '1')
                .replace('O', 'o')
                .replace('0', 'o')
        }
        else _input
        return doDecode(input)
    }

    private fun doDecode(input: String): ByteArray {
        if (input.length == 0) {
            // paying with the same coin
            return ByteArray(0)
        }
        val input58 = ByteArray(input.length)
        //
        // Transform the String to a base58 byte sequence
        //
        for (i in 0 until input.length) {
            val c = input[i]
            var digit58 = -1
            if (c.code >= 0 && c.code < 128) {
                digit58 = INDEXES[c.code]
            }
            if (digit58 < 0) {
                throw IllegalArgumentException("Not a Base58 input: $input")
            }
            input58[i] = digit58.toByte()
        }

        //
        // Count leading zeroes
        //
        var zeroCount = 0
        while (zeroCount < input58.size && input58[zeroCount].toInt() == 0) {
            ++zeroCount
        }

        //
        // The encoding
        //
        val temp = ByteArray(input.length)
        var j = temp.size
        var startAt = zeroCount
        while (startAt < input58.size) {
            val mod = divmod256(input58, startAt)
            if (input58[startAt].toInt() == 0) {
                ++startAt
            }
            temp[--j] = mod
        }

        //
        // Do no add extra leading zeroes, move j to first non null byte.
        //
        while (j < temp.size && temp[j].toInt() == 0) {
            ++j
        }
        return copyOfRange(temp, j - zeroCount, temp.size)
    }

    private fun divmod58(number: ByteArray, startAt: Int): Byte {
        var remainder = 0
        for (i in startAt until number.size) {
            val digit256 = number[i].toInt() and 0xFF
            val temp = remainder * BASE_256 + digit256
            number[i] = (temp / BASE_58).toByte()
            remainder = temp % BASE_58
        }
        return remainder.toByte()
    }

    private fun divmod256(number58: ByteArray, startAt: Int): Byte {
        var remainder = 0
        for (i in startAt until number58.size) {
            val digit58 = number58[i].toInt() and 0xFF
            val temp = remainder * BASE_58 + digit58
            number58[i] = (temp / BASE_256).toByte()
            remainder = temp % BASE_256
        }
        return remainder.toByte()
    }

    private fun copyOfRange(source: ByteArray, from: Int, to: Int): ByteArray {
        return source.sliceArray( from until to)
    }

    /**
     * Encode data using Safe58 (see [encode]) adding CRC8 check code allowing checking integrity on decode (safe
     * against mistypes and like). Use [decodeWithCrc] to check and decode.
     */
    fun encodeWithCrc(data: ByteArray): String {
        return encode( byteArrayOf(CRC.crc8(data).toByte()) + data )
    }

    class InvalidCrcException: Exception("CRC does not match")

    /**
     * Decode safe58 encoded value with crc8 check code. Use [encodeWithCrc] to obtain it. Uses safe mode (not strict).
     * @param encoded encoded string
     * @return decoded value
     * @throws InvalidCrcException if the crc code does not match
     */
    fun decodeWithCrc(encoded: String): ByteArray {
        val all = decode(encoded)
        val data = all.sliceArray(1 until all.size)
        val crc1 = all.first().toUByte()
        val crc2 = CRC.crc8(data)
        if( crc1 != crc2 ) throw InvalidCrcException()
        return data
    }
}
