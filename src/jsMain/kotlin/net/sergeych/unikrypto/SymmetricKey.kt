package net.sergeych.unikrypto

import kotlinx.coroutines.await

class SymmetricKeyImpl(id: ByteArray,bits: ByteArray): SymmetricKey(id) {

    private val key = Unicrypto.SymmetricKey(SymmetricKeyParams(bits))

    override suspend fun etaEncrypt(plaintext: ByteArray): ByteArray = key.etaEncrypt(plaintext).await()

    override suspend fun etaDecrypt(ciphertext: ByteArray): ByteArray = key.etaDecrypt(ciphertext).await()

    override suspend fun keyBytes(): ByteArray = key.pack()

    init {
        if( bits.size != 32) throw IllegalArgumentException("wrong bits size, needs 32 got ${bits.size}")
    }
}

actual val SymmetricKeys: SymmetricKeyProvider = object : SymmetricKeyProvider {
    override fun create(keyBytes: ByteArray,id: ByteArray): SymmetricKey =
        SymmetricKeyImpl(id, keyBytes)

    override fun random() = SymmetricKeyImpl(Unicrypto.randomBytes(32),Unicrypto.randomBytes(32))

}