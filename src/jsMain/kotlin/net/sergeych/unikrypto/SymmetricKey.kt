package net.sergeych.unikrypto

import kotlinx.coroutines.await

class SymmetricKeyImpl(id: KeyIdentity, override val keyBytes: ByteArray): SymmetricKey(id) {

    private val key = Unicrypto.SymmetricKey(SymmetricKeyParams(keyBytes))

    override suspend fun etaEncrypt(plaintext: ByteArray): ByteArray = key.etaEncrypt(plaintext).await()

    override suspend fun etaDecrypt(ciphertext: ByteArray): ByteArray = key.etaDecrypt(ciphertext).await()

    override suspend fun pack(): ByteArray = key.pack()

    init {
        if( keyBytes.size != 32) throw IllegalArgumentException("wrong bits size, needs 32 got ${keyBytes.size}")
    }
}

actual val SymmetricKeys: SymmetricKeyProvider = object : SymmetricKeyProvider {
    override val keySizes = arrayOf(32)

    override fun create(keyBytes: ByteArray,id: KeyIdentity): SymmetricKey =
        SymmetricKeyImpl(id, keyBytes)

    override fun random() = SymmetricKeyImpl(BytesId.random(),Unicrypto.randomBytes(32))

}

actual suspend fun HashAlgorithm.digest(source: ByteArray): ByteArray
        = Unicrypto.SHA.getDigest(this.toUniversa(), source).await()