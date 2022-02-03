package net.sergeych.unikrypto

class SymmetricKeyImpl(id: KeyIdentity, override val keyBytes: ByteArray): SymmetricKey(id) {

    val key = Unicrypto.SymmetricKey(SymmetricKeyParams(keyBytes.toUint8Array()))

    override fun etaEncrypt(plaintext: ByteArray): ByteArray = key.etaEncryptSync(plaintext.toUint8Array()).toByteArray()

    override fun etaDecrypt(ciphertext: ByteArray): ByteArray = key.etaDecryptSync(ciphertext.toUint8Array()).toByteArray()

    override val packed: ByteArray by lazy { key.pack().toByteArray() }

    init {
        if( keyBytes.size != 32) throw IllegalArgumentException("wrong bits size, needs 32 got ${keyBytes.size}")
    }
}

actual val SymmetricKeys: SymmetricKeyProvider = object : SymmetricKeyProvider {
    override val keySizes = arrayOf(32)

    override fun create(keyBytes: ByteArray,id: KeyIdentity): SymmetricKey = SymmetricKeyImpl(id, keyBytes)

    override fun random() = SymmetricKeyImpl(BytesId.random(),Unicrypto.randomBytes(32).toByteArray())

}

actual fun HashAlgorithm.digest(vararg source: ByteArray): ByteArray {
    val df = Unicrypto.SHA(toUniversa())
    for( s in source) df.putSync(s.toUint8Array())
    return df.digest().toByteArray()
}