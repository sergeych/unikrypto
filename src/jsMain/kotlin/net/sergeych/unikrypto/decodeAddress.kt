package net.sergeych.unikrypto

class KeyAddressJs(val address: Unicrypto.KeyAddress) : KeyAddress {
    override val asBytes: ByteArray by lazy { address.asBinary.toByteArray() }
    override val asString: String by lazy { address.asString }

    override fun matches(key: PublicKey): Boolean = address.isMatchingKey(key.universaKey)
}

actual fun decodeAddress(text: String): KeyAddress = KeyAddressJs(Unicrypto.KeyAddress(text))

actual fun decodeAddress(data: ByteArray): KeyAddress =
    KeyAddressJs(Unicrypto.KeyAddress(data.toUint8Array()))

@Suppress("unused")
fun KeyAddress.universaAddress() = (this as KeyAddressJs).address

