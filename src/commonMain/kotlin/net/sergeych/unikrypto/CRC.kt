@file:OptIn(ExperimentalUnsignedTypes::class)

package net.sergeych.unikrypto

/**
 * Common interfacte for all CRC variants. See [crc16], [crc32] and [crc8] for useful shortcuts.
 */
interface CRC<T> {
    val lookupTable: List<T>
    val value: T

    fun update(inputs: UByteArray)
    fun reset()

    fun update(input: UByte) {
        update(ubyteArrayOf(input))
    }

    fun update(inputs: ByteArray) {
        update(inputs.toUByteArray())
    }

    companion object {
        /**
         * Calculate crc8 for a data array using a given polynomial (uses CRC8-Bluetooth's polynomial by default)
         */
        fun crc8(data: ByteArray, polynomial: UByte = 0xA7.toUByte()): UByte =
            CRC8(polynomial).also { it.update(data) }.value

        /**
         * Calculate CRC16 for a data array using a given polynomial (CRC16-CCITT polynomial (0x1021) by default)
         */
        fun crc16(data: ByteArray, polynomial: UShort = 0x1021.toUShort()): UShort =
            CRC16(polynomial).also { it.update(data) }.value

        /**
         * Calculate crc32 for a given data and polynomial (using CRC32 polynomial by default)
         */
        fun crc32(data: ByteArray, polynomial: UInt = 0x04C11DB7.toUInt()): UInt =
            CRC32(polynomial).also { it.update(data) }.value
    }
}

infix fun UShort.shl(bitCount: Int): UShort = (this.toUInt() shl bitCount).toUShort()
infix fun UShort.shr(bitCount: Int): UShort = (this.toUInt() shr bitCount).toUShort()

infix fun UByte.shl(bitCount: Int): UByte = (this.toUInt() shl bitCount).toUByte()
infix fun UByte.shr(bitCount: Int): UByte = (this.toUInt() shr bitCount).toUByte()

fun UByte.toBigEndianUShort(): UShort = this.toUShort() shl 8
fun UByte.toBigEndianUInt(): UInt = this.toUInt() shl 24