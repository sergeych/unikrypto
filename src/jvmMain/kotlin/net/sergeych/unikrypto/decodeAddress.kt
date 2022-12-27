package net.sergeych.unikrypto


class KeyAddressJvm(val address: com.icodici.crypto.KeyAddress): KeyAddress {
    override val asBytes: ByteArray by lazy { address.packed }
    override val asString: String by lazy { address.toString() }

    override fun matches(key: PublicKey): Boolean = address.isMatchingKey(key.universaKey)
}

actual fun decodeAddress(data: ByteArray): KeyAddress = KeyAddressJvm(com.icodici.crypto.KeyAddress(data))

actual fun decodeAddress(text: String): KeyAddress = KeyAddressJvm(com.icodici.crypto.KeyAddress(text))

@Suppress("unused")
fun KeyAddress.universaAddress() = (this as KeyAddressJvm).address