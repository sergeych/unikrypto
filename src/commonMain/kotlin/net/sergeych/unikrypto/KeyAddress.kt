package net.sergeych.unikrypto

/**
 * The key address is a special kind of assymmetric key identity used in Universa. It has special mechanics
 * to prevent it from mistyping: crc code inside and special character representation (safe58) that corrects
 * error for most "look-alike" characters. As mistyping key address may lead to severe losses, we recommend
 * use KeyAddress and its [AddressId], which is already automatically used with [PublicKey] and [PrivateKey].
 *
 * Please note that for security reasons we only implement "long" addresses, short ones, used in early years
 * of universa blockchain, are less strong and may be vulnerable in the quantum computing era.
 */
interface KeyAddress {
    /**
     * Byte representation, includes integrity code (crc)
     */
    val asBytes: ByteArray

    /**
     * String representation, Safe58 of [asBytes]
     */
    val asString: String

    /**
     * Check the key matches this address
     */
    fun matches(key: PublicKey): Boolean
    /**
     * Check the key's public part matches this address
     */
    fun matches(key: PrivateKey) = matches(key.publicKey)

    companion object {
        /**
         * Decode safe58 text address format and checks its integrity
         */
        fun of(textAddress: String) = decodeAddress(textAddress)

        /**
         * Decode keyaddres from bytes and checks its integrity
         */
        fun of(bytes: ByteArray) = decodeAddress(bytes)
    }
}

expect fun decodeAddress(data: ByteArray): KeyAddress

expect fun decodeAddress(text: String): KeyAddress