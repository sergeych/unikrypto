package net.sergeych.unikrypto

actual val SymmetricKeys: SymmetricKeyProvider = object : SymmetricKeyProvider {
    override val keySizes = arrayOf(32)

    override fun create(keyBytes: ByteArray, id: KeyIdentity): SymmetricKey =
        SymmetricKeyImpl(id, com.icodici.crypto.SymmetricKey(keyBytes))


    override fun random(): SymmetricKey =
        SymmetricKeyImpl(BytesId.random(), com.icodici.crypto.SymmetricKey())
}

actual suspend fun HashAlgorithm.digest(source: ByteArray): ByteArray =
    this.toUnicrypto().createDigest().digest(source)