package net.sergeych.unikrypto

actual val SymmetricKeys: SymmetricKeyProvider = object : SymmetricKeyProvider {
    override val keySizes = arrayOf(32)

    override fun create(keyBytes: ByteArray, id: KeyIdentity): SymmetricKey =
        SymmetricKeyImpl(id, com.icodici.crypto.SymmetricKey(keyBytes))


    override fun random(): SymmetricKey =
        SymmetricKeyImpl(BytesId.random(), com.icodici.crypto.SymmetricKey())
}

actual fun HashAlgorithm.digest(vararg source: ByteArray): ByteArray {
    val df = this.toUnicrypto().createDigest()
    for( s in source) df.update(s)
    return df.digest()
}