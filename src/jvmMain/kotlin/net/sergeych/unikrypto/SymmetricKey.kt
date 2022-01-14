package net.sergeych.unikrypto

internal class SymmetricKeyImpl(id: KeyIdentity,private val key: com.icodici.crypto.SymmetricKey): SymmetricKey(id) {

    override suspend fun pack(): ByteArray = key.pack()
    override val keyBytes: ByteArray by lazy { key.pack() }

    override suspend fun etaEncrypt(plaintext: ByteArray): ByteArray = key.etaEncrypt(plaintext)

    override suspend fun etaDecrypt(ciphertext: ByteArray): ByteArray = key.etaDecrypt(ciphertext)
}