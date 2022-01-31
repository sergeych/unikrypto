package net.sergeych.unikrypto

internal class SymmetricKeyImpl(id: KeyIdentity,private val key: com.icodici.crypto.SymmetricKey): SymmetricKey(id) {

    override val packed: ByteArray by lazy { key.pack() }

    override val keyBytes: ByteArray by lazy { key.pack() }

    override fun etaEncrypt(plaintext: ByteArray): ByteArray = key.etaEncrypt(plaintext)

    override fun etaDecrypt(ciphertext: ByteArray): ByteArray = key.etaDecrypt(ciphertext)
}
