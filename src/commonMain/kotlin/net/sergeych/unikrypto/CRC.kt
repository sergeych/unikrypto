package net.sergeych.unikrypto

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
}

infix fun UShort.shl(bitCount: Int): UShort = (this.toUInt() shl bitCount).toUShort()
infix fun UShort.shr(bitCount: Int): UShort = (this.toUInt() shr bitCount).toUShort()

infix fun UByte.shl(bitCount: Int): UByte = (this.toUInt() shl bitCount).toUByte()
infix fun UByte.shr(bitCount: Int): UByte = (this.toUInt() shr bitCount).toUByte()

fun UByte.toBigEndianUShort(): UShort = this.toUShort() shl 8
fun UByte.toBigEndianUInt(): UInt = this.toUInt() shl 24