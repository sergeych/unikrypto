package net.sergeych.unikrypto

internal class SymmetricKeyImpl(id: ByteArray,private val key: com.icodici.crypto.SymmetricKey): SymmetricKey(id) {

    override suspend fun pack(): ByteArray = key.pack()

    override suspend fun etaEncrypt(plaintext: ByteArray): ByteArray = key.etaEncrypt(plaintext)

    override suspend fun etaDecrypt(ciphertext: ByteArray): ByteArray = key.etaDecrypt(ciphertext)
}